
;; STX-DataShield

;; Error codes
(define-constant ERROR-UNAUTHORIZED-ACCESS (err u1))
(define-constant ERROR-USER-ALREADY-EXISTS (err u2))
(define-constant ERROR-USER-NOT-FOUND (err u3))
(define-constant ERROR-INVALID-PERMISSION-LEVEL (err u4))
(define-constant ERROR-ACCESS-PERIOD-EXPIRED (err u5))
(define-constant ERROR-INVALID-INPUT (err u6))

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
