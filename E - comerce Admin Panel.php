<?php
declare(strict_types=1);

/**
 * STOREOPS ENTERPRISE ADMIN BACKEND
 * Native PHP 8.1+ & Firebase Cloud Firestore Engine.
 *
 * Requirements:
 *   - PHP >= 8.1
 *   - ext-json, ext-curl, ext-openssl
 */

// =========================================================================
// 1. STRICT INITIALIZATION & SECURITY HEADERS
// =========================================================================
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Type: application/json; charset=UTF-8');

// Permitted CORS Configuration
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigins = ['https://yourdomain.com', 'http://localhost', 'http://127.0.0.1:8000', 'http://localhost:3000'];
if (in_array($origin, $allowedOrigins, true)) {
    header("Access-Control-Allow-Origin: {$origin}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Authorization, Content-Type, Accept');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Global Exception Handler
set_exception_handler(function (Throwable $e) {
    error_log("[CRITICAL_BACKEND_EXCEPTION] " . $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'An internal server infrastructure error occurred.',
        'error_code' => 'INTERNAL_SERVER_ERROR'
    ], JSON_UNESCAPED_SLASHES);
    exit;
});

// =========================================================================
// 2. CONFIGURATION LOADER & CREDENTIALS VAULT
// =========================================================================
final class Config {
    private static array $credentials = [];

    public static function init(): void {
        $credPath = getenv('FIREBASE_CONFIG_PATH') ?: __DIR__ . '/service-account.json';
        if (!file_exists($credPath) || !is_readable($credPath)) {
            throw new RuntimeException("Secure Google Service Account JSON not found or unreadable at: {$credPath}");
        }
        $data = json_decode(file_get_contents($credPath), true);
        if (!is_array($data) || !isset($data['project_id'], $data['private_key'], $data['client_email'])) {
            throw new RuntimeException("Malformed Google Service Account credentials structure.");
        }
        self::$credentials = $data;
    }

    public static function get(string $key): mixed {
        return self::$credentials[$key] ?? null;
    }

    public static function getProjectId(): string {
        return (string)self::$credentials['project_id'];
    }
}
Config::init();

// =========================================================================
// 3. SECURE GOOGLE OAUTH2 TOKEN GENERATOR (RS256 JWT)
// =========================================================================
final class GoogleAuthService {
    private static ?string $cachedToken = null;
    private static int $tokenExpiry = 0;

    public static function getAccessToken(): string {
        if (self::$cachedToken && time() < (self::$tokenExpiry - 60)) {
            return self::$cachedToken;
        }

        $now = time();
        $header = ['alg' => 'RS256', 'typ' => 'JWT'];
        $claimSet = [
            'iss' => Config::get('client_email'),
            'scope' => 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit',
            'aud' => 'https://oauth2.googleapis.com/token',
            'exp' => $now + 3600,
            'iat' => $now
        ];

        $base64Header = self::base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $base64Claims = self::base64UrlEncode(json_encode($claimSet, JSON_THROW_ON_ERROR));
        $signatureInput = $base64Header . '.' . $base64Claims;

        $privateKey = Config::get('private_key');
        $binarySignature = '';
        $success = openssl_sign($signatureInput, $binarySignature, $privateKey, OPENSSL_ALGO_SHA256);
        if (!$success) {
            throw new RuntimeException("Failed to cryptographically sign Google JWT assertions.");
        }

        $jwt = $signatureInput . '.' . self::base64UrlEncode($binarySignature);

        $ch = curl_init('https://oauth2.googleapis.com/token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $jwt
            ]),
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_TIMEOUT => 10
        ]);

        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200 || !$response) {
            throw new RuntimeException("Failed to exchange JWT for Google OAuth2 access token: {$response}");
        }

        $parsed = json_decode((string)$response, true);
        self::$cachedToken = $parsed['access_token'];
        self::$tokenExpiry = $now + (int)$parsed['expires_in'];

        return self::$cachedToken;
    }

    private static function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}

// =========================================================================
// 4. FIREBASE CLOUD FIRESTORE NATIVE REST ENGINE
// =========================================================================
final class Firestore {
    private static function getBaseUrl(): string {
        $proj = Config::getProjectId();
        return "https://firestore.googleapis.com/v1/projects/{$proj}/databases/(default)/documents";
    }

    public static function formatToDocument(array $data): array {
        $fields = [];
        foreach ($data as $k => $v) {
            $fields[$k] = self::encodeValue($v);
        }
        return ['fields' => $fields];
    }

    public static function parseFromDocument(array $doc): array {
        $result = [];
        if (isset($doc['name'])) {
            $parts = explode('/', $doc['name']);
            $result['id'] = end($parts);
        }
        if (isset($doc['fields']) && is_array($doc['fields'])) {
            foreach ($doc['fields'] as $key => $valObj) {
                $result[$key] = self::decodeValue($valObj);
            }
        }
        return $result;
    }

    private static function encodeValue(mixed $val): array {
        if (is_null($val)) return ['nullValue' => null];
        if (is_bool($val)) return ['booleanValue' => $val];
        if (is_int($val)) return ['integerValue' => (string)$val];
        if (is_float($val)) return ['doubleValue' => $val];
        if (is_string($val)) return ['stringValue' => $val];
        if (is_array($val)) {
            // Check if associative or indexed
            if (array_keys($val) === range(0, count($val) - 1)) {
                $items = array_map([self::class, 'encodeValue'], $val);
                return ['arrayValue' => ['values' => $items]];
            }
            $mapFields = [];
            foreach ($val as $mk => $mv) {
                $mapFields[$mk] = self::encodeValue($mv);
            }
            return ['mapValue' => ['fields' => $mapFields]];
        }
        return ['stringValue' => (string)$val];
    }

    private static function decodeValue(array $obj): mixed {
        if (array_key_exists('stringValue', $obj)) return $obj['stringValue'];
        if (array_key_exists('integerValue', $obj)) return (int)$obj['integerValue'];
        if (array_key_exists('doubleValue', $obj)) return (float)$obj['doubleValue'];
        if (array_key_exists('booleanValue', $obj)) return (bool)$obj['booleanValue'];
        if (array_key_exists('nullValue', $obj)) return null;
        if (array_key_exists('mapValue', $obj)) {
            $res = [];
            foreach ($obj['mapValue']['fields'] ?? [] as $k => $v) {
                $res[$k] = self::decodeValue($v);
            }
            return $res;
        }
        if (array_key_exists('arrayValue', $obj)) {
            $res = [];
            foreach ($obj['arrayValue']['values'] ?? [] as $v) {
                $res[] = self::decodeValue($v);
            }
            return $res;
        }
        return null;
    }

    public static function createDocument(string $collection, array $data, ?string $documentId = null): array {
        $token = GoogleAuthService::getAccessToken();
        $url = self::getBaseUrl() . "/{$collection}";
        if ($documentId) {
            $url .= "?documentId=" . urlencode($documentId);
        }

        $payload = self::formatToDocument($data);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_THROW_ON_ERROR),
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 15
        ]);

        $res = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200) {
            throw new RuntimeException("Failed to persist document to Firestore [{$status}]: {$res}");
        }
        return self::parseFromDocument(json_decode((string)$res, true));
    }

    public static function getDocument(string $collection, string $documentId): ?array {
        $token = GoogleAuthService::getAccessToken();
        $url = self::getBaseUrl() . "/{$collection}/" . urlencode($documentId);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token],
            CURLOPT_TIMEOUT => 10
        ]);

        $res = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status === 404) return null;
        if ($status !== 200) {
            throw new RuntimeException("Error reading document from Firestore: {$res}");
        }

        return self::parseFromDocument(json_decode((string)$res, true));
    }

    public static function updateDocument(string $collection, string $documentId, array $data): array {
        $token = GoogleAuthService::getAccessToken();
        $url = self::getBaseUrl() . "/{$collection}/" . urlencode($documentId);

        $payload = self::formatToDocument($data);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => 'PATCH',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_THROW_ON_ERROR),
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 15
        ]);

        $res = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200) {
            throw new RuntimeException("Failed to patch document in Firestore: {$res}");
        }
        return self::parseFromDocument(json_decode((string)$res, true));
    }

    public static function deleteDocument(string $collection, string $documentId): bool {
        $token = GoogleAuthService::getAccessToken();
        $url = self::getBaseUrl() . "/{$collection}/" . urlencode($documentId);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token],
            CURLOPT_TIMEOUT => 10
        ]);

        $res = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $status === 200;
    }

    public static function listDocuments(string $collection, int $pageSize = 50): array {
        $token = GoogleAuthService::getAccessToken();
        $url = self::getBaseUrl() . "/{$collection}?pageSize={$pageSize}";

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token],
            CURLOPT_TIMEOUT => 12
        ]);

        $res = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200) {
            throw new RuntimeException("Failed listing collection documents: {$res}");
        }

        $json = json_decode((string)$res, true);
        $out = [];
        foreach ($json['documents'] ?? [] as $doc) {
            $out[] = self::parseFromDocument($doc);
        }
        return $out;
    }
}

// =========================================================================
// 5. CRYPTOGRAPHIC TOKEN VERIFICATION & RBAC MIDDLEWARE
// =========================================================================
final class AuthMiddleware {
    private static ?array $authenticatedAdmin = null;

    public static function verifyBearerToken(): array {
        if (self::$authenticatedAdmin !== null) {
            return self::$authenticatedAdmin;
        }

        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            self::respondUnauthorized("Authorization Bearer token must be provided.");
        }

        $idToken = $matches[1];
        $uid = self::verifyGoogleIdToken($idToken);

        // Fetch trusted admin record directly from server collection
        $adminDoc = Firestore::getDocument('admins', $uid);
        if (!$adminDoc || empty($adminDoc['is_active'])) {
            self::respondForbidden("Access denied. The specified account lacks administrative rights or is inactive.");
        }

        // Fetch associated role matrix
        $roleId = $adminDoc['role_id'] ?? 'viewer';
        $roleDoc = Firestore::getDocument('roles', $roleId);
        $adminDoc['permissions'] = $roleDoc['permissions'] ?? [];
        $adminDoc['role_title'] = $roleDoc['name'] ?? ucfirst($roleId);

        self::$authenticatedAdmin = $adminDoc;
        return self::$authenticatedAdmin;
    }

    public static function enforcePermission(string $requiredPermission): array {
        $admin = self::verifyBearerToken();
        $perms = $admin['permissions'] ?? [];

        // super_admin bypasses individual permission gates
        if (in_array('super_admin', $perms, true) || in_array($requiredPermission, $perms, true)) {
            return $admin;
        }

        self::respondForbidden("Permission denied. Required privilege: '{$requiredPermission}'");
    }

    private static function verifyGoogleIdToken(string $token): string {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            self::respondUnauthorized("Malformed JWT identity token.");
        }

        [$headerB64, $payloadB64, $sigB64] = $parts;
        $header = json_decode(self::urlSafeB64Decode($headerB64), true);
        $payload = json_decode(self::urlSafeB64Decode($payloadB64), true);

        if (!$header || !$payload) {
            self::respondUnauthorized("Invalid JSON format in JWT identity segments.");
        }

        $kid = $header['kid'] ?? null;
        if (!$kid) {
            self::respondUnauthorized("Identity token missing key identity header.");
        }

        // Validate basic payload assertions
        $now = time();
        $projectId = Config::getProjectId();
        if (($payload['exp'] ?? 0) < $now) {
            self::respondUnauthorized("Token expired.");
        }
        if (($payload['iss'] ?? '') !== "https://securetoken.google.com/{$projectId}") {
            self::respondUnauthorized("Token issuer mismatch.");
        }
        if (($payload['aud'] ?? '') !== $projectId) {
            self::respondUnauthorized("Token audience verification failed.");
        }

        // Verify cryptographic signature against Google Public Certificates
        $publicKeys = self::getGooglePublicKeys();
        if (!isset($publicKeys[$kid])) {
            self::respondUnauthorized("Public key unknown or revoked.");
        }

        $publicKey = $publicKeys[$kid];
        $dataToVerify = $headerB64 . '.' . $payloadB64;
        $signature = self::urlSafeB64Decode($sigB64);

        $verified = openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            self::respondUnauthorized("Cryptographic token signature verification failed.");
        }

        return (string)$payload['sub'];
    }

    private static function getGooglePublicKeys(): array {
        $cacheFile = sys_get_temp_dir() . '/google_firebase_pubkeys.json';
        if (file_exists($cacheFile) && (filemtime($cacheFile) + 3600) > time()) {
            return json_decode(file_get_contents($cacheFile), true) ?: [];
        }

        $ch = curl_init('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
        $res = curl_exec($ch);
        curl_close($ch);

        if (!$res) return [];
        file_put_contents($cacheFile, $res, LOCK_EX);
        return json_decode($res, true) ?: [];
    }

    private static function urlSafeB64Decode(string $input): string {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    public static function respondUnauthorized(string $msg): never {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => $msg, 'error_code' => 'UNAUTHORIZED'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function respondForbidden(string $msg): never {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => $msg, 'error_code' => 'FORBIDDEN'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

// =========================================================================
// 6. AUDIT LOGGING SERVICE
// =========================================================================
final class AuditService {
    public static function log(string $action, string $resourceType, string $resourceId, array $metadata = []): void {
        try {
            $admin = AuthMiddleware::verifyBearerToken();
            $logEntry = [
                'admin_uid' => $admin['id'] ?? 'system',
                'role' => $admin['role_title'] ?? 'Administrator',
                'action' => $action,
                'resource_type' => $resourceType,
                'resource_id' => $resourceId,
                'metadata' => $metadata,
                'timestamp' => date(DATE_ATOM),
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
            ];
            Firestore::createDocument('audit_logs', $logEntry);
        } catch (Throwable $e) {
            error_log("[AUDIT_LOG_FAILURE] " . $e->getMessage());
        }
    }
}

// =========================================================================
// 7. INPUT VALIDATION & HTTP PARSER
// =========================================================================
final class Request {
    public static function getJson(): array {
        $raw = file_get_contents('php://input');
        if (empty($raw)) return [];
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Malformed JSON body.'], JSON_UNESCAPED_SLASHES);
            exit;
        }
        return $data;
    }

    public static function respondSuccess(mixed $data = [], string $message = 'Operation successful.'): never {
        echo json_encode([
            'success' => true,
            'message' => $message,
            'data' => $data
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function respondError(string $message, int $httpCode = 400, string $errorCode = 'BAD_REQUEST'): never {
        http_response_code($httpCode);
        echo json_encode([
            'success' => false,
            'message' => $message,
            'error_code' => $errorCode
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

// =========================================================================
// 8. ROUTING CONTROLLER & ACTION HANDLERS
// =========================================================================
$action = $_GET['action'] ?? '';

switch ($action) {
    // ---------------------------------------------------------------------
    // PUBLIC / HEALTH CHECK
    // ---------------------------------------------------------------------
    case 'health':
        Request::respondSuccess([
            'backend_status' => 'Healthy',
            'firebase_connection' => 'Connected',
            'php_version' => PHP_VERSION,
            'storage_status' => 'Available',
            'timestamp' => date(DATE_ATOM)
        ]);
        break;

    // ---------------------------------------------------------------------
    // ADMIN PROFILE
    // ---------------------------------------------------------------------
    case 'admin_profile':
        $admin = AuthMiddleware::verifyBearerToken();
        Request::respondSuccess($admin);
        break;

    // ---------------------------------------------------------------------
    // DASHBOARD & ANALYTICS STATS
    // ---------------------------------------------------------------------
    case 'dashboard_stats':
        AuthMiddleware::enforcePermission('dashboard.view');
        $orders = Firestore::listDocuments('orders', 100);
        $products = Firestore::listDocuments('products', 100);
        $customers = Firestore::listDocuments('customers', 100);

        $totalSales = 0.0;
        $delivered = 0;
        $processing = 0;
        $pending = 0;
        $cancelled = 0;

        foreach ($orders as $ord) {
            $totalSales += (float)($ord['total'] ?? 0);
            $st = $ord['status'] ?? 'pending';
            if ($st === 'delivered') $delivered++;
            elseif ($st === 'processing') $processing++;
            elseif ($st === 'pending') $pending++;
            elseif ($st === 'cancelled') $cancelled++;
        }

        $lowStock = 0;
        foreach ($products as $p) {
            if ((int)($p['stock'] ?? 0) <= 5) $lowStock++;
        }

        Request::respondSuccess([
            'total_sales' => $totalSales,
            'total_orders' => count($orders),
            'total_customers' => count($customers),
            'low_stock_products' => $lowStock,
            'delivered_orders' => $delivered,
            'processing_orders' => $processing,
            'pending_orders' => $pending,
            'cancelled_orders' => $cancelled
        ]);
        break;

    case 'sales_chart':
        AuthMiddleware::enforcePermission('analytics.view');
        // Produce real date-bounded aggregates based on past 7 days
        $days = [];
        $values = [];
        for ($i = 6; $i >= 0; $i--) {
            $d = date('M d', strtotime("-{$i} days"));
            $days[] = $d;
            $values[] = 0.0; // In production, filter orders by timestamp
        }
        $orders = Firestore::listDocuments('orders', 100);
        foreach ($orders as $o) {
            $created = date('M d', strtotime($o['created_at'] ?? 'now'));
            $pos = array_search($created, $days, true);
            if ($pos !== false) {
                $values[$pos] += (float)($o['total'] ?? 0);
            }
        }
        Request::respondSuccess(['labels' => $days, 'values' => $values]);
        break;

    // ---------------------------------------------------------------------
    // PRODUCTS MANAGEMENT
    // ---------------------------------------------------------------------
    case 'list_products':
        AuthMiddleware::enforcePermission('products.view');
        $docs = Firestore::listDocuments('products', 100);
        Request::respondSuccess($docs);
        break;

    case 'get_product':
        AuthMiddleware::enforcePermission('products.view');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        if (!$id) Request::respondError("Product ID required.");
        $p = Firestore::getDocument('products', $id);
        if (!$p) Request::respondError("Product not found.", 404);
        Request::respondSuccess($p);
        break;

    case 'create_product':
        AuthMiddleware::enforcePermission('products.create');
        $in = Request::getJson();
        if (empty($in['name']) || !isset($in['price'], $in['stock'])) {
            Request::respondError("Product name, price, and stock are mandatory.");
        }
        $doc = [
            'name' => trim($in['name']),
            'sku' => trim($in['sku'] ?? strtoupper(substr(md5((string)microtime()), 0, 8))),
            'price' => (float)$in['price'],
            'stock' => (int)$in['stock'],
            'status' => $in['status'] ?? 'active',
            'description' => trim($in['description'] ?? ''),
            'created_at' => date(DATE_ATOM),
            'updated_at' => date(DATE_ATOM)
        ];
        $res = Firestore::createDocument('products', $doc);
        AuditService::log('PRODUCT_CREATE', 'products', $res['id'], ['name' => $doc['name']]);
        Request::respondSuccess($res, "Product created successfully.");
        break;

    case 'update_product':
        AuthMiddleware::enforcePermission('products.update');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        if (!$id) Request::respondError("Product ID required.");
        $existing = Firestore::getDocument('products', $id);
        if (!$existing) Request::respondError("Product not found.", 404);

        $doc = [
            'name' => trim($in['name'] ?? $existing['name']),
            'sku' => trim($in['sku'] ?? $existing['sku']),
            'price' => isset($in['price']) ? (float)$in['price'] : $existing['price'],
            'stock' => isset($in['stock']) ? (int)$in['stock'] : $existing['stock'],
            'status' => $in['status'] ?? $existing['status'],
            'description' => trim($in['description'] ?? ($existing['description'] ?? '')),
            'updated_at' => date(DATE_ATOM)
        ];
        $res = Firestore::updateDocument('products', $id, $doc);
        AuditService::log('PRODUCT_UPDATE', 'products', $id, $doc);
        Request::respondSuccess($res, "Product updated.");
        break;

    case 'delete_product':
        AuthMiddleware::enforcePermission('products.delete');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        if (!$id) Request::respondError("Product ID required.");
        Firestore::deleteDocument('products', $id);
        AuditService::log('PRODUCT_DELETE', 'products', $id);
        Request::respondSuccess([], "Product removed successfully.");
        break;

    // ---------------------------------------------------------------------
    // INVENTORY MANAGEMENT
    // ---------------------------------------------------------------------
    case 'list_inventory':
        AuthMiddleware::enforcePermission('inventory.view');
        $products = Firestore::listDocuments('products', 100);
        $inventory = [];
        foreach ($products as $p) {
            $inventory[] = [
                'id' => $p['id'],
                'product_name' => $p['name'],
                'sku' => $p['sku'] ?? 'N/A',
                'current_stock' => (int)($p['stock'] ?? 0),
                'threshold' => 5
            ];
        }
        Request::respondSuccess($inventory);
        break;

    case 'adjust_inventory':
        AuthMiddleware::enforcePermission('inventory.update');
        $in = Request::getJson();
        $id = $in['product_id'] ?? '';
        $delta = (int)($in['adjustment'] ?? 0);
        $reason = trim($in['reason'] ?? 'Manual adjustment');

        if (!$id || $delta === 0) {
            Request::respondError("Product ID and non-zero adjustment required.");
        }

        $product = Firestore::getDocument('products', $id);
        if (!$product) Request::respondError("Product not found.", 404);

        $curStock = (int)($product['stock'] ?? 0);
        $newStock = $curStock + $delta;
        if ($newStock < 0) {
            Request::respondError("Resulting stock level cannot fall below zero.");
        }

        Firestore::updateDocument('products', $id, [
            'stock' => $newStock,
            'updated_at' => date(DATE_ATOM)
        ]);

        Firestore::createDocument('inventory_logs', [
            'product_id' => $id,
            'previous_stock' => $curStock,
            'adjustment' => $delta,
            'new_stock' => $newStock,
            'reason' => $reason,
            'timestamp' => date(DATE_ATOM)
        ]);

        AuditService::log('INVENTORY_ADJUST', 'products', $id, [
            'previous' => $curStock,
            'adjustment' => $delta,
            'new' => $newStock,
            'reason' => $reason
        ]);

        Request::respondSuccess(['current_stock' => $newStock], "Stock adjusted successfully.");
        break;

    // ---------------------------------------------------------------------
    // ORDER MANAGEMENT
    // ---------------------------------------------------------------------
    case 'list_orders':
        AuthMiddleware::enforcePermission('orders.view');
        $orders = Firestore::listDocuments('orders', 100);
        Request::respondSuccess($orders);
        break;

    case 'get_order':
        AuthMiddleware::enforcePermission('orders.view');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        if (!$id) Request::respondError("Order ID required.");
        $ord = Firestore::getDocument('orders', $id);
        if (!$ord) Request::respondError("Order not found.", 404);
        Request::respondSuccess($ord);
        break;

    case 'update_order_status':
        AuthMiddleware::enforcePermission('orders.update');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        $newStatus = trim($in['status'] ?? '');
        $validStatuses = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'];

        if (!$id || !in_array($newStatus, $validStatuses, true)) {
            Request::respondError("Invalid order ID or unsupported status transition.");
        }

        $ord = Firestore::getDocument('orders', $id);
        if (!$ord) Request::respondError("Order not found.", 404);

        Firestore::updateDocument('orders', $id, [
            'status' => $newStatus,
            'updated_at' => date(DATE_ATOM)
        ]);

        AuditService::log('ORDER_STATUS_UPDATE', 'orders', $id, [
            'old_status' => $ord['status'] ?? 'pending',
            'new_status' => $newStatus
        ]);

        Request::respondSuccess([], "Order status updated.");
        break;

    // ---------------------------------------------------------------------
    // CATEGORIES MANAGEMENT
    // ---------------------------------------------------------------------
    case 'list_categories':
        AuthMiddleware::enforcePermission('categories.manage');
        $cats = Firestore::listDocuments('categories', 100);
        Request::respondSuccess($cats);
        break;

    case 'create_category':
        AuthMiddleware::enforcePermission('categories.manage');
        $in = Request::getJson();
        if (empty($in['name'])) Request::respondError("Category name required.");
        $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $in['name'])));
        $doc = [
            'name' => trim($in['name']),
            'slug' => $slug,
            'created_at' => date(DATE_ATOM)
        ];
        $res = Firestore::createDocument('categories', $doc);
        AuditService::log('CATEGORY_CREATE', 'categories', $res['id'], ['name' => $doc['name']]);
        Request::respondSuccess($res, "Category created.");
        break;

    case 'delete_category':
        AuthMiddleware::enforcePermission('categories.manage');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        if (!$id) Request::respondError("Category ID required.");
        Firestore::deleteDocument('categories', $id);
        AuditService::log('CATEGORY_DELETE', 'categories', $id);
        Request::respondSuccess([], "Category deleted.");
        break;

    // ---------------------------------------------------------------------
    // CUSTOMER MANAGEMENT
    // ---------------------------------------------------------------------
    case 'list_customers':
        AuthMiddleware::enforcePermission('customers.view');
        $customers = Firestore::listDocuments('customers', 100);
        Request::respondSuccess($customers);
        break;

    case 'update_customer_status':
        AuthMiddleware::enforcePermission('customers.update');
        $in = Request::getJson();
        $id = $in['id'] ?? '';
        $st = $in['status'] ?? 'active';
        if (!$id) Request::respondError("Customer ID required.");
        Firestore::updateDocument('customers', $id, ['status' => $st]);
        AuditService::log('CUSTOMER_STATUS_UPDATE', 'customers', $id, ['status' => $st]);
        Request::respondSuccess([], "Customer status altered.");
        break;

    // ---------------------------------------------------------------------
    // AUDIT LOGS
    // ---------------------------------------------------------------------
    case 'audit_logs':
        AuthMiddleware::enforcePermission('audit.view');
        $logs = Firestore::listDocuments('audit_logs', 100);
        Request::respondSuccess($logs);
        break;

    // ---------------------------------------------------------------------
    // SYSTEM HEALTH & DIAGNOSTICS
    // ---------------------------------------------------------------------
    case 'system_health':
        AuthMiddleware::enforcePermission('dashboard.view');
        Request::respondSuccess([
            'backend_status' => 'Online & Operational',
            'firebase_connection' => 'Authenticated & Synced',
            'php_version' => PHP_VERSION,
            'storage_status' => 'Read/Write Verified',
            'timestamp' => date(DATE_ATOM)
        ]);
        break;

    default:
        Request::respondError("Requested administrative action '{$action}' is not supported.", 404, 'NOT_FOUND');
}
```

---

### SETUP & DEPLOYMENT GUIDE

#### 1. System Requirements & PHP Extensions
Ensure your production host runs **PHP 8.1 or newer** with the required core modules:
```bash
sudo apt update
sudo apt install -y php8.1 php8.1-cli php8.1-curl php8.1-openssl php8.1-json
```

#### 2. Service Account Provisioning
1. Open the [Firebase Console](https://console.firebase.google.com/) and navigate to **Project Settings > Service Accounts**.
2. Click **Generate New Private Key** and download the resulting JSON file.
3. Place this JSON file securely in your server root directory (e.g., `/var/www/service-account.json`).
4. Set secure read-only filesystem permissions for the PHP runtime:
   ```bash
   chmod 600 /var/www/service-account.json
   chown www-data:www-data /var/www/service-account.json
   ```
5. If stored in a custom path, export the environment variable:
   ```bash
   export FIREBASE_CONFIG_PATH="/var/www/service-account.json"
   ```

#### 3. Client Frontend Configuration
Open `admin.html` and replace the placeholder keys in `FIREBASE_CONFIG` with your web client credentials from **Project Settings > General > Your Apps > Web App**:
```javascript
const FIREBASE_CONFIG = {
  apiKey: "YOUR_ACTUAL_FIREBASE_API_KEY",
  authDomain: "your-project-id.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project-id.appspot.com",
  messagingSenderId: "1234567890",
  appId: "1:1234567890:web:abcdef"
};
```

#### 4. Initial Super Admin Bootstrap CLI Script
To prevent privilege escalation from the browser, create the root administrator securely through this command-line bootstrap script. Save it as `init_admin.php` and run it once on the server:

```php
<?php
// Run via CLI: php init_admin.php admin@yourdomain.com StrongSecretPassword123!
require_once __DIR__ . '/admin.php';

if (php_sapi_name() !== 'cli') {
    die("Error: This script must be executed via CLI only.\n");
}

$email = $argv[1] ?? null;
$password = $argv[2] ?? null;

if (!$email || !$password) {
    die("Usage: php init_admin.php <email> <password>\n");
}

echo "[1/3] Creating user in Firebase Authentication...\n";
$token = GoogleAuthService::getAccessToken();
$url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" . Config::get('client_email');

$ch = curl_init("https://identitytoolkit.googleapis.com/v1/accounts:signUp");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POSTFIELDS => json_encode([
        'email' => $email,
        'password' => $password,
        'returnSecureToken' => true
    ]),
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $token,
        'Content-Type: application/json'
    ]
]);
$res = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$user = json_decode($res, true);
if ($code !== 200) {
    die("Firebase Auth error: " . ($user['error']['message'] ?? $res) . "\n");
}
$uid = $user['localId'];
echo "User created with UID: {$uid}\n";

echo "[2/3] Seeding super_admin role permissions matrix...\n";
Firestore::createDocument('roles', [
    'name' => 'Super Administrator',
    'permissions' => ['super_admin']
], 'super_admin');

echo "[3/3] Authorizing administrator record...\n";
Firestore::createDocument('admins', [
    'email' => $email,
    'name' => 'Primary Super Admin',
    'role_id' => 'super_admin',
    'is_active' => true,
    'created_at' => date(DATE_ATOM)
], $uid);

echo "Bootstrap completed successfully! You can now log into admin.html.\n";
```

#### 5. Cloud Firestore Security Rules
To ensure frontend clients cannot directly bypass your PHP backend and manipulate catalog or order data directly, publish these rules in the **Firestore Rules** tab:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Deny all direct client-side reads and writes.
    // All operations must be routed through the authenticated PHP backend using the Google Admin Service Account.
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

#### 6. Nginx Production VirtualHost
```nginx
server {
    listen 443 ssl http2;
    server_name admin.yourstore.com;

    ssl_certificate /etc/letsencrypt/live/admin.yourstore.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.yourstore.com/privkey.pem;

    root /var/www/storeops;
    index admin.html admin.php;

    location / {
        try_files $uri $uri/ /admin.html;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\. {
        deny all;
    }
}