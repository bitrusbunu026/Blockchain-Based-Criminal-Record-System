(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_RECORD_NOT_FOUND (err u101))
(define-constant ERR_RECORD_ALREADY_EXISTS (err u102))
(define-constant ERR_INVALID_STATUS (err u103))
(define-constant ERR_RECORD_SEALED (err u104))
(define-constant ERR_INSUFFICIENT_PERMISSIONS (err u105))
(define-constant ERR_INVALID_CONSENT (err u106))

(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_SEALED u2)
(define-constant STATUS_DISCLOSED u3)

(define-constant ROLE_ADMIN u1)
(define-constant ROLE_COURT u2)
(define-constant ROLE_LAW_ENFORCEMENT u3)
(define-constant ROLE_VIEWER u4)

(define-map authorized-users principal uint)

(define-map criminal-records
  { record-id: uint }
  {
    subject-id: (string-ascii 64),
    case-number: (string-ascii 32),
    offense-type: (string-ascii 128),
    conviction-date: uint,
    sentence: (string-ascii 256),
    status: uint,
    created-by: principal,
    created-at: uint,
    last-modified: uint,
    consent-required: bool,
    consent-given: bool,
    sealed-by: (optional principal),
    sealed-at: (optional uint),
    disclosure-count: uint
  }
)

(define-map record-access-log
  { record-id: uint, access-id: uint }
  {
    accessor: principal,
    access-type: (string-ascii 32),
    timestamp: uint,
    authorized: bool
  }
)

(define-map subject-consent
  { subject-id: (string-ascii 64) }
  {
    consent-given: bool,
    consent-date: uint,
    consent-expiry: (optional uint)
  }
)

(define-data-var next-record-id uint u1)
(define-data-var next-access-id uint u1)

(define-private (is-authorized (user principal) (required-role uint))
  (match (map-get? authorized-users user)
    role (>= role required-role)
    false
  )
)

(define-private (log-access (record-id uint) (access-type (string-ascii 32)) (authorized bool))
  (let ((access-id (var-get next-access-id)))
    (map-set record-access-log
      { record-id: record-id, access-id: access-id }
      {
        accessor: tx-sender,
        access-type: access-type,
        timestamp: stacks-block-height,
        authorized: authorized
      }
    )
    (var-set next-access-id (+ access-id u1))
    (ok access-id)
  )
)

(define-private (check-consent (subject-id (string-ascii 64)))
  (match (map-get? subject-consent { subject-id: subject-id })
    consent-data 
      (and 
        (get consent-given consent-data)
        (match (get consent-expiry consent-data)
          expiry (< stacks-block-height expiry)
          true
        )
      )
    false
  )
)

(define-public (initialize-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (map-set authorized-users CONTRACT_OWNER ROLE_ADMIN)
    (ok true)
  )
)

(define-public (add-authorized-user (user principal) (role uint))
  (begin
    (asserts! (is-authorized tx-sender ROLE_ADMIN) ERR_UNAUTHORIZED)
    (asserts! (<= role ROLE_VIEWER) ERR_INVALID_STATUS)
    (map-set authorized-users user role)
    (ok true)
  )
)

(define-public (remove-authorized-user (user principal))
  (begin
    (asserts! (is-authorized tx-sender ROLE_ADMIN) ERR_UNAUTHORIZED)
    (asserts! (not (is-eq user CONTRACT_OWNER)) ERR_UNAUTHORIZED)
    (map-delete authorized-users user)
    (ok true)
  )
)

(define-public (create-record 
  (subject-id (string-ascii 64))
  (case-number (string-ascii 32))
  (offense-type (string-ascii 128))
  (conviction-date uint)
  (sentence (string-ascii 256))
  (consent-required bool)
)
  (let ((record-id (var-get next-record-id)))
    (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? criminal-records { record-id: record-id })) ERR_RECORD_ALREADY_EXISTS)
    
    (map-set criminal-records
      { record-id: record-id }
      {
        subject-id: subject-id,
        case-number: case-number,
        offense-type: offense-type,
        conviction-date: conviction-date,
        sentence: sentence,
        status: STATUS_ACTIVE,
        created-by: tx-sender,
        created-at: stacks-block-height,
        last-modified: stacks-block-height,
        consent-required: consent-required,
        consent-given: (if consent-required (check-consent subject-id) true),
        sealed-by: none,
        sealed-at: none,
        disclosure-count: u0
      }
    )
    
    (var-set next-record-id (+ record-id u1))
    (unwrap-panic (log-access record-id "CREATE" true))
    (ok record-id)
  )
)

(define-public (seal-record (record-id uint))
  (match (map-get? criminal-records { record-id: record-id })
    record-data
      (begin
        (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
        (asserts! (not (is-eq (get status record-data) STATUS_SEALED)) ERR_RECORD_SEALED)
        
        (map-set criminal-records
          { record-id: record-id }
          (merge record-data {
            status: STATUS_SEALED,
            last-modified: stacks-block-height,
            sealed-by: (some tx-sender),
            sealed-at: (some stacks-block-height)
          })
        )
        
        (unwrap-panic (log-access record-id "SEAL" true))
        (ok true)
      )
    ERR_RECORD_NOT_FOUND
  )
)

(define-public (disclose-record (record-id uint))
  (match (map-get? criminal-records { record-id: record-id })
    record-data
      (begin
        (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
        (asserts! (is-eq (get status record-data) STATUS_SEALED) ERR_INVALID_STATUS)
        
        (if (get consent-required record-data)
          (asserts! (check-consent (get subject-id record-data)) ERR_INVALID_CONSENT)
          true
        )
        
        (map-set criminal-records
          { record-id: record-id }
          (merge record-data {
            status: STATUS_DISCLOSED,
            last-modified: stacks-block-height,
            disclosure-count: (+ (get disclosure-count record-data) u1)
          })
        )
        
        (unwrap-panic (log-access record-id "DISCLOSE" true))
        (ok true)
      )
    ERR_RECORD_NOT_FOUND
  )
)

(define-public (set-subject-consent 
  (subject-id (string-ascii 64))
  (consent-given bool)
  (expiry-blocks (optional uint))
)
  (begin
    (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
    
    (map-set subject-consent
      { subject-id: subject-id }
      {
        consent-given: consent-given,
        consent-date: stacks-block-height,
        consent-expiry: (match expiry-blocks
          blocks (some (+ stacks-block-height blocks))
          none
        )
      }
    )
    (ok true)
  )
)

(define-read-only (get-record (record-id uint))
  (match (map-get? criminal-records { record-id: record-id })
    record-data
      (if (is-eq (get status record-data) STATUS_SEALED)
        (if (is-authorized tx-sender ROLE_COURT)
          (ok record-data)
          ERR_INSUFFICIENT_PERMISSIONS)
        (if (is-authorized tx-sender ROLE_VIEWER)
          (if (get consent-required record-data)
            (if (check-consent (get subject-id record-data))
              (ok record-data)
              ERR_INVALID_CONSENT)
            (ok record-data))
          ERR_INSUFFICIENT_PERMISSIONS))
    ERR_RECORD_NOT_FOUND)
)
(define-read-only (get-record-status (record-id uint))
  (match (map-get? criminal-records { record-id: record-id })
    record-data (ok (get status record-data))
    ERR_RECORD_NOT_FOUND
  )
)

(define-read-only (get-user-role (user principal))
  (ok (map-get? authorized-users user))
)

(define-read-only (get-subject-consent-status (subject-id (string-ascii 64)))
  (ok (map-get? subject-consent { subject-id: subject-id }))
)

(define-read-only (get-access-log (record-id uint) (access-id uint))
  (ok (map-get? record-access-log { record-id: record-id, access-id: access-id }))
)

(define-read-only (verify-record-integrity (record-id uint))
  (match (map-get? criminal-records { record-id: record-id })
    record-data
      (ok {
        record-exists: true,
        created-at: (get created-at record-data),
        last-modified: (get last-modified record-data),
        created-by: (get created-by record-data),
        current-status: (get status record-data),
        disclosure-count: (get disclosure-count record-data)
      })
    (ok { record-exists: false, created-at: u0, last-modified: u0, created-by: CONTRACT_OWNER, current-status: u0, disclosure-count: u0 })
  )
)