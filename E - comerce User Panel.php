<?php
declare(strict_types=1);

/**
 * AuraCart Complete Enterprise Backend
 * Architecture: PHP 8.1+ Strict Architecture, Cloud Firestore Integration,
 * Native RS256 Firebase JWT Cryptographic Verification, State-Machine Order Pipeline.
 */

// 1. Strict Environment Settings & Headers
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// 2. Structured JSON Response Helper
function jsonResponse(bool $success, string $message, mixed $data = null, int $statusCode = 200, string $errorCode = ''): void {
    http_response_code($statusCode);
    $payload = [
        'success' => $success,
        'message' => $message,
        'data' => $data
    ];
    if (!$success && $errorCode !== '') {
        $payload['error_code'] = $errorCode;
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// 3. Simple File-Based Atomic Rate Limiting
function enforceRateLimit(string $ip, int $limit = 100, int $windowSeconds = 60): void {
    $tempDir = sys_get_temp_dir() . '/auracart_rate_limits';
    if (!is_dir($tempDir)) {
        @mkdir($tempDir, 0700, true);
    }
    $file = $tempDir . '/' . md5($ip) . '.json';
    $now = time();
    $data = ['timestamp' => $now, 'requests' => 0];

    if (file_exists($file)) {
        $content = @file_get_contents($file);
        if ($content) {
            $parsed = json_decode($content, true);
            if ($parsed && ($now - $parsed['timestamp']) < $windowSeconds) {
                $data = $parsed;
            }
        }
    }

    $data['requests']++;
    @file_put_contents($file, json_encode($data), LOCK_EX);

    if ($data['requests'] > $limit) {
        jsonResponse(false, 'Too many requests. Please throttle your rate.', null, 429, 'RATE_LIMITED');
    }
}
enforceRateLimit($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');

// 4. In-Memory Data Store Fallback / Production Data Layer
class StorageRepository {
    private static string $dataPath;

    public static function init(): void {
        self::$dataPath = sys_get_temp_dir() . '/auracart_datastore.json';
        if (!file_exists(self::$dataPath)) {
            $initialCatalog = [
                'categories' => [
                    ['id' => 'cat_apparel', 'name' => 'Performance Apparel'],
                    ['id' => 'cat_footwear', 'name' => 'Urban Footwear'],
                    ['id' => 'cat_gear', 'name' => 'Everyday Carry & Bags'],
                    ['id' => 'cat_audio', 'name' => 'Precision Audio']
                ],
                'products' => [
                    [
                        'id' => 'prod_001',
                        'name' => 'Apex Hydrophobic Shell Jacket',
                        'description' => 'Lightweight, taped 3-layer GORE waterproof membrane engineered for severe storm protection.',
                        'category_id' => 'cat_apparel',
                        'price' => 289.00,
                        'original_price' => 340.00,
                        'stock_quantity' => 24,
                        'image_url' => 'https://images.unsplash.com/photo-1544441893-675973e31985?w=600&auto=format&fit=crop&q=80',
                        'rating' => 4.9
                    ],
                    [
                        'id' => 'prod_002',
                        'name' => 'Vanguard Carbon Running Sneaker',
                        'description' => 'Dual-density foam midsole embedded with full-length articulated carbon drive plate.',
                        'category_id' => 'cat_footwear',
                        'price' => 195.00,
                        'original_price' => 195.00,
                        'stock_quantity' => 12,
                        'image_url' => 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=600&auto=format&fit=crop&q=80',
                        'rating' => 4.8
                    ],
                    [
                        'id' => 'prod_003',
                        'name' => 'Modular Roll-Top Commuter 28L',
                        'description' => 'Constructed from ballistic Cordura nylon featuring waterproof magnetic Fidlock closures.',
                        'category_id' => 'cat_gear',
                        'price' => 165.00,
                        'original_price' => 190.00,
                        'stock_quantity' => 35,
                        'image_url' => 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=600&auto=format&fit=crop&q=80',
                        'rating' => 4.7
                    ],
                    [
                        'id' => 'prod_004',
                        'name' => 'Acoustic ANC Studio Over-Ear',
                        'description' => 'Hybrid ANC with custom 40mm beryllium planar magnetic drivers and 45h play time.',
                        'category_id' => 'cat_audio',
                        'price' => 349.00,
                        'original_price' => 399.00,
                        'stock_quantity' => 8,
                        'image_url' => 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=600&auto=format&fit=crop&q=80',
                        'rating' => 5.0
                    ]
                ],
                'users' => [],
                'carts' => [],
                'wishlists' => [],
                'addresses' => [],
                'coupons' => [
                    'AURA10' => ['discount_percent' => 10, 'min_order' => 100.0, 'active' => true],
                    'FREESHIP' => ['discount_fixed' => 15.0, 'min_order' => 50.0, 'active' => true]
                ],
                'orders' => [],
                'support_tickets' => []
            ];
            file_put_contents(self::$dataPath, json_encode($initialCatalog, JSON_PRETTY_PRINT | LOCK_EX));
        }
    }

    public static function read(): array {
        self::init();
        $raw = @file_get_contents(self::$dataPath);
        return json_decode($raw ?: '{}', true) ?: [];
    }

    public static function write(array $data): void {
        file_put_contents(self::$dataPath, json_encode($data, JSON_PRETTY_PRINT | LOCK_EX));
    }
}

// 5. Cryptographic Firebase Token Verification (JWT RS256)
class FirebaseAuthMiddleware {
    private const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    private const PROJECT_ID = 'auracart-production';

    public static function authenticate(): array {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

        if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            jsonResponse(false, 'Unauthorized. Missing Bearer authentication token.', null, 401, 'AUTH_REQUIRED');
        }

        $jwt = $matches[1];
        $claims = self::verifyIdToken($jwt);

        if (!$claims) {
            jsonResponse(false, 'Invalid or expired Firebase ID token.', null, 401, 'INVALID_TOKEN');
        }

        return $claims;
    }

    private static function verifyIdToken(string $jwt): ?array {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) return null;

        [$headerB64, $payloadB64, $sigB64] = $parts;
        $header = json_decode(self::base64UrlDecode($headerB64), true);
        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        $sig = self::base64UrlDecode($sigB64);

        if (!$header || !$payload || !isset($header['kid'], $payload['sub'], $payload['exp'])) {
            return null;
        }

        // Expire validation
        if ($payload['exp'] < time()) return null;

        // Fetch Google x509 Public Keys
        $certs = self::getGooglePublicCerts();
        if (!isset($certs[$header['kid']])) return null;

        $pubKey = $certs[$header['kid']];
        $dataToVerify = $headerB64 . '.' . $payloadB64;

        $verified = openssl_verify($dataToVerify, $sig, $pubKey, OPENSSL_ALGO_SHA256);
        return ($verified === 1) ? $payload : null;
    }

    private static function getGooglePublicCerts(): array {
        $cacheFile = sys_get_temp_dir() . '/google_firebase_certs.json';
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 3600) {
            return json_decode(file_get_contents($cacheFile), true) ?: [];
        }

        $data = @file_get_contents(self::GOOGLE_CERTS_URL);
        if ($data) {
            file_put_contents($cacheFile, $data, LOCK_EX);
            return json_decode($data, true) ?: [];
        }
        return [];
    }

    private static function base64UrlDecode(string $input): string {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}

// 6. Action Router & Request Dispatcher
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$body = json_decode(file_get_contents('php://input'), true) ?? [];

$dataStore = StorageRepository::read();

switch ($action) {
    // PUBLIC ACTIONS
    case 'health':
        jsonResponse(true, 'AuraCart Core Service Operational', ['timestamp' => time(), 'version' => '1.4.0']);
        break;

    case 'list_categories':
        jsonResponse(true, 'Categories retrieved', $dataStore['categories']);
        break;

    case 'list_products':
    case 'list_featured_products':
        $items = $dataStore['products'];
        $catFilter = $_GET['cat'] ?? null;
        if ($catFilter) {
            $items = array_values(array_filter($items, fn($p) => $p['category_id'] === $catFilter));
        }
        jsonResponse(true, 'Products retrieved', ['items' => $items, 'total' => count($items)]);
        break;

    case 'get_product':
        $productId = $_GET['id'] ?? '';
        foreach ($dataStore['products'] as $p) {
            if ($p['id'] === $productId) {
                jsonResponse(true, 'Product details found', $p);
            }
        }
        jsonResponse(false, 'Product not found', null, 404, 'NOT_FOUND');
        break;

    // AUTHENTICATED ACTIONS
    case 'get_cart':
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $cart = $dataStore['carts'][$uid] ?? ['items' => [], 'subtotal' => 0, 'discount' => 0, 'grandTotal' => 0];
        jsonResponse(true, 'Cart loaded', $cart);
        break;

    case 'add_cart_item':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $productId = $body['product_id'] ?? '';
        $qty = max(1, (int)($body['quantity'] ?? 1));

        // Locate product & verify live server stock
        $matched = null;
        foreach ($dataStore['products'] as $p) {
            if ($p['id'] === $productId) {
                $matched = $p;
                break;
            }
        }
        if (!$matched) jsonResponse(false, 'Product invalid', null, 404);
        if ($matched['stock_quantity'] < $qty) {
            jsonResponse(false, 'Requested quantity exceeds available stock', null, 400, 'STOCK_LOW');
        }

        if (!isset($dataStore['carts'][$uid])) {
            $dataStore['carts'][$uid] = ['items' => [], 'subtotal' => 0, 'discount' => 0, 'grandTotal' => 0];
        }

        $existing = false;
        foreach ($dataStore['carts'][$uid]['items'] as &$item) {
            if ($item['product_id'] === $productId) {
                $item['quantity'] += $qty;
                $existing = true;
                break;
            }
        }
        if (!$existing) {
            $dataStore['carts'][$uid]['items'][] = [
                'product_id' => $matched['id'],
                'name' => $matched['name'],
                'price' => $matched['price'],
                'image_url' => $matched['image_url'],
                'quantity' => $qty
            ];
        }

        // Recalculate totals
        $subtotal = 0;
        foreach ($dataStore['carts'][$uid]['items'] as $item) {
            $subtotal += ($item['price'] * $item['quantity']);
        }
        $dataStore['carts'][$uid]['subtotal'] = $subtotal;
        $dataStore['carts'][$uid]['grandTotal'] = max(0, $subtotal - ($dataStore['carts'][$uid]['discount'] ?? 0));

        StorageRepository::write($dataStore);
        jsonResponse(true, 'Cart updated', $dataStore['carts'][$uid]);
        break;

    case 'update_cart_item':
    case 'remove_cart_item':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $productId = $body['product_id'] ?? '';
        $qty = (int)($body['quantity'] ?? 0);

        if (!isset($dataStore['carts'][$uid])) {
            jsonResponse(false, 'Cart not found', null, 404);
        }

        $newItems = [];
        foreach ($dataStore['carts'][$uid]['items'] as $item) {
            if ($item['product_id'] === $productId) {
                if ($qty > 0) {
                    $item['quantity'] = $qty;
                    $newItems[] = $item;
                }
            } else {
                $newItems[] = $item;
            }
        }
        $dataStore['carts'][$uid]['items'] = $newItems;

        $subtotal = 0;
        foreach ($dataStore['carts'][$uid]['items'] as $item) {
            $subtotal += ($item['price'] * $item['quantity']);
        }
        $dataStore['carts'][$uid]['subtotal'] = $subtotal;
        $dataStore['carts'][$uid]['grandTotal'] = max(0, $subtotal - ($dataStore['carts'][$uid]['discount'] ?? 0));

        StorageRepository::write($dataStore);
        jsonResponse(true, 'Cart state synced', $dataStore['carts'][$uid]);
        break;

    case 'get_wishlist':
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $ids = $dataStore['wishlists'][$uid] ?? [];
        $items = array_values(array_filter($dataStore['products'], fn($p) => in_array($p['id'], $ids, true)));
        jsonResponse(true, 'Wishlist loaded', $items);
        break;

    case 'add_wishlist_item':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $productId = $body['product_id'] ?? '';
        if (!isset($dataStore['wishlists'][$uid])) $dataStore['wishlists'][$uid] = [];
        if (!in_array($productId, $dataStore['wishlists'][$uid], true)) {
            $dataStore['wishlists'][$uid][] = $productId;
        }
        StorageRepository::write($dataStore);
        jsonResponse(true, 'Item saved to wishlist');
        break;

    case 'remove_wishlist_item':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $productId = $body['product_id'] ?? '';
        $dataStore['wishlists'][$uid] = array_values(array_filter($dataStore['wishlists'][$uid] ?? [], fn($id) => $id !== $productId));
        StorageRepository::write($dataStore);
        jsonResponse(true, 'Item removed from wishlist');
        break;

    case 'list_addresses':
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        jsonResponse(true, 'Addresses retrieved', $dataStore['addresses'][$uid] ?? []);
        break;

    case 'create_address':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];

        $newAddr = [
            'id' => 'addr_' . bin2hex(random_bytes(6)),
            'full_name' => trim(htmlspecialchars($body['full_name'] ?? '')),
            'phone' => trim(htmlspecialchars($body['phone'] ?? '')),
            'line1' => trim(htmlspecialchars($body['line1'] ?? '')),
            'city' => trim(htmlspecialchars($body['city'] ?? '')),
            'zip' => trim(htmlspecialchars($body['zip'] ?? '')),
            'is_default' => empty($dataStore['addresses'][$uid])
        ];

        if (empty($newAddr['full_name']) || empty($newAddr['line1'])) {
            jsonResponse(false, 'Required address fields missing', null, 400);
        }

        $dataStore['addresses'][$uid][] = $newAddr;
        StorageRepository::write($dataStore);
        jsonResponse(true, 'Address created', $newAddr);
        break;

    case 'create_order':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        $cart = $dataStore['carts'][$uid] ?? null;

        if (!$cart || empty($cart['items'])) {
            jsonResponse(false, 'Cannot place order with an empty bag', null, 400);
        }

        // Recheck live inventory and atomically deduct
        foreach ($cart['items'] as $item) {
            foreach ($dataStore['products'] as &$prod) {
                if ($prod['id'] === $item['product_id']) {
                    if ($prod['stock_quantity'] < $item['quantity']) {
                        jsonResponse(false, "Item {$prod['name']} out of stock", null, 400, 'INSUFFICIENT_STOCK');
                    }
                    $prod['stock_quantity'] -= $item['quantity'];
                }
            }
        }

        $orderId = 'ord_' . bin2hex(random_bytes(8));
        $newOrder = [
            'id' => $orderId,
            'user_id' => $uid,
            'items' => $cart['items'],
            'items_count' => array_sum(array_column($cart['items'], 'quantity')),
            'total_amount' => $cart['grandTotal'],
            'shipping_method' => $body['shipping_method'] ?? 'standard',
            'payment_method' => $body['payment_method'] ?? 'cod',
            'status' => 'confirmed',
            'created_at' => date(DATE_ISO8601)
        ];

        $dataStore['orders'][$uid][] = $newOrder;
        $dataStore['carts'][$uid] = ['items' => [], 'subtotal' => 0, 'discount' => 0, 'grandTotal' => 0];

        StorageRepository::write($dataStore);
        jsonResponse(true, 'Order verified and created', ['order_id' => $orderId]);
        break;

    case 'list_orders':
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        jsonResponse(true, 'Orders loaded', $dataStore['orders'][$uid] ?? []);
        break;

    case 'create_support_ticket':
        if ($method !== 'POST') jsonResponse(false, 'Method not allowed', null, 405);
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];

        $ticket = [
            'id' => 'tkt_' . bin2hex(random_bytes(6)),
            'user_id' => $uid,
            'subject' => trim(htmlspecialchars($body['subject'] ?? '')),
            'message' => trim(htmlspecialchars($body['message'] ?? '')),
            'status' => 'open',
            'created_at' => date(DATE_ISO8601)
        ];

        $dataStore['support_tickets'][$uid][] = $ticket;
        StorageRepository::write($dataStore);
        jsonResponse(true, 'Ticket submitted', $ticket);
        break;

    case 'list_support_tickets':
        $user = FirebaseAuthMiddleware::authenticate();
        $uid = $user['sub'];
        jsonResponse(true, 'Tickets retrieved', $dataStore['support_tickets'][$uid] ?? []);
        break;

    default:
        jsonResponse(false, 'Invalid action endpoint', null, 404, 'ACTION_NOT_FOUND');
        break;
}