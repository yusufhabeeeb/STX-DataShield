
;; STX-DataShield

;; Error codes
(define-constant ERROR-UNAUTHORIZED-ACCESS (err u1))
(define-constant ERROR-USER-ALREADY-EXISTS (err u2))
(define-constant ERROR-USER-NOT-FOUND (err u3))
(define-constant ERROR-INVALID-PERMISSION-LEVEL (err u4))
(define-constant ERROR-ACCESS-PERIOD-EXPIRED (err u5))
(define-constant ERROR-INVALID-INPUT (err u6))

;; Public variables
(define-data-var contract-administrator principal tx-sender)
(define-data-var minimum-required-permission uint u1)
(define-data-var maximum-allowed-permission uint u5)


;; Data maps
(define-map registered-users 
    principal 
    {
        is-active: bool,
        encrypted-data-hash: (optional (buff 32)),
        profile-update-timestamp: uint,
        user-permission-level: uint
    }
)

(define-map user-access-registry
    { data-owner: principal, data-requester: principal }
    {
        access-granted: bool,
        access-expiry-height: uint,
        granted-permission-level: uint
    }
)

(define-map privacy-data-categories
    uint
    {
        category-name: (string-ascii 64),
        minimum-permission-level: uint
    }
)


;;;;;;;;;; READ ONLY FUNCTIONS ;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Read-only functions
(define-read-only (get-user-profile-data (target-user principal))
    (map-get? registered-users target-user)
)

(define-read-only (verify-data-access (data-owner principal) (data-requester principal))
    (some (validate-access-permission data-owner data-requester))
)

(define-read-only (get-detailed-access-permissions (data-owner principal) (data-requester principal))
    (map-get? user-access-registry { data-owner: data-owner, data-requester: data-requester })
)

;; Initialize contract
(begin
    (map-set privacy-data-categories u1 { category-name: "Basic-Profile", minimum-permission-level: u1 })
    (map-set privacy-data-categories u2 { category-name: "Personal-Details", minimum-permission-level: u2 })
    (map-set privacy-data-categories u3 { category-name: "Sensitive-Information", minimum-permission-level: u3 })
    (map-set privacy-data-categories u4 { category-name: "Financial-Records", minimum-permission-level: u4 })
    (map-set privacy-data-categories u5 { category-name: "Medical-History", minimum-permission-level: u5 })
)


;; Private functions
(define-private (is-contract-admin (caller-address principal)) 
    (is-eq caller-address (var-get contract-administrator))
)

(define-private (validate-access-permission (data-owner principal) (data-requester principal))
    (let (
        (access-details (default-to 
            { access-granted: false, access-expiry-height: u0, granted-permission-level: u0 }
            (map-get? user-access-registry { data-owner: data-owner, data-requester: data-requester })
        ))
    )
    (and 
        (get access-granted access-details)
        (> (get access-expiry-height access-details) stacks-block-height)
    ))
)


(define-private (validate-buff-32 (input (optional (buff 32))))
    (match input
        buff (is-eq (len buff) u32)
        false
    )
)

(define-private (is-valid-user (user principal))
    (is-some (map-get? registered-users user))
)


;; Public functions
(define-public (register-new-user (initial-data-hash (optional (buff 32))))
    (let (
        (requesting-address tx-sender)
    )
    (asserts! (is-none (map-get? registered-users requesting-address)) ERROR-USER-ALREADY-EXISTS)
    (asserts! (validate-buff-32 initial-data-hash) ERROR-INVALID-INPUT)
    (ok (map-set registered-users 
        requesting-address
        {
            is-active: true,
            encrypted-data-hash: initial-data-hash,
            profile-update-timestamp: stacks-block-height,
            user-permission-level: (var-get minimum-required-permission)
        }
    )))
)

(define-public (update-encrypted-data (updated-data-hash (buff 32)))
    (let (
        (requesting-address tx-sender)
        (existing-user-data (unwrap! (map-get? registered-users requesting-address) ERROR-USER-NOT-FOUND))
    )
    (asserts! (is-eq (len updated-data-hash) u32) ERROR-INVALID-INPUT)
    (ok (map-set registered-users
        requesting-address
        (merge existing-user-data {
            encrypted-data-hash: (some updated-data-hash),
            profile-update-timestamp: stacks-block-height
        })
    )))
)

(define-public (grant-data-access (requesting-party principal) (access-permission-level uint) (access-duration uint))
    (let (
        (data-owner-address tx-sender)
        (owner-profile-data (unwrap! (map-get? registered-users data-owner-address) ERROR-USER-NOT-FOUND))
        (calculated-expiry-height (+ stacks-block-height access-duration))
    )
    (asserts! (is-valid-user requesting-party) ERROR-INVALID-INPUT)
    (asserts! (<= access-permission-level (get user-permission-level owner-profile-data)) ERROR-INVALID-PERMISSION-LEVEL)
    (asserts! (< stacks-block-height calculated-expiry-height) ERROR-INVALID-INPUT)
    (ok (map-set user-access-registry
        { data-owner: data-owner-address, data-requester: requesting-party }
        {
            access-granted: true,
            access-expiry-height: calculated-expiry-height,
            granted-permission-level: access-permission-level
        }
    )))
)

(define-public (revoke-data-access (access-requester principal))
    (let (
        (data-owner-address tx-sender)
    )
    (asserts! (is-valid-user access-requester) ERROR-INVALID-INPUT)
    (ok (map-delete user-access-registry { data-owner: data-owner-address, data-requester: access-requester }))
))

(define-public (request-user-data-access (target-data-owner principal))
    (let (
        (requesting-address tx-sender)
        (access-permissions (unwrap! (map-get? user-access-registry { data-owner: target-data-owner, data-requester: requesting-address }) ERROR-UNAUTHORIZED-ACCESS))
    )
    (asserts! (validate-access-permission target-data-owner requesting-address) ERROR-ACCESS-PERIOD-EXPIRED)
    (ok (map-get? registered-users target-data-owner))
))

(define-public (modify-user-permission-level (target-user principal) (new-permission-level uint))
    (let (
        (admin-address tx-sender)
    )
    (asserts! (is-contract-admin admin-address) ERROR-UNAUTHORIZED-ACCESS)
    (asserts! (is-valid-user target-user) ERROR-INVALID-INPUT)
    (asserts! (and (>= new-permission-level (var-get minimum-required-permission)) 
                   (<= new-permission-level (var-get maximum-allowed-permission))) 
              ERROR-INVALID-PERMISSION-LEVEL)
    (match (map-get? registered-users target-user)
        existing-user-data (ok (map-set registered-users
            target-user
            (merge existing-user-data {
                user-permission-level: new-permission-level,
                profile-update-timestamp: stacks-block-height
            })))
        ERROR-USER-NOT-FOUND
    )
))
