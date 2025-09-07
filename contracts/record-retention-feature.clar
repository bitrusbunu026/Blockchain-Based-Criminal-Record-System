(define-constant STATUS_EXPIRED u4)
(define-constant ERR_RECORD_EXPIRED (err u107))
(define-constant ERR_INVALID_RETENTION (err u108))
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_RECORD_NOT_FOUND (err u101))

(define-constant ROLE_COURT u2)

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

(define-constant RETENTION_JUVENILE u2190)
(define-constant RETENTION_MISDEMEANOR u4380)
(define-constant RETENTION_FELONY u8760)
(define-constant RETENTION_PERMANENT u999999999)

(define-map record-retention
  { record-id: uint }
  {
    retention-period: uint,
    expiry-block: uint,
    auto-expire: bool,
    archived-at: (optional uint),
    expiry-reason: (optional (string-ascii 64))
  }
)

(define-private (is-record-expired (record-id uint))
  (match (map-get? record-retention { record-id: record-id })
    retention-data
      (and 
        (get auto-expire retention-data)
        (>= stacks-block-height (get expiry-block retention-data))
      )
    false
  )
)

(define-private (calculate-expiry-block (retention-period uint))
  (+ stacks-block-height retention-period)
)

(define-public (set-record-retention 
  (record-id uint)
  (retention-period uint)
  (auto-expire bool)
)
  (begin
    (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
    (asserts! (is-some (map-get? criminal-records { record-id: record-id })) ERR_RECORD_NOT_FOUND)
    (asserts! (> retention-period u0) ERR_INVALID_RETENTION)
    
    (map-set record-retention
      { record-id: record-id }
      {
        retention-period: retention-period,
        expiry-block: (calculate-expiry-block retention-period),
        auto-expire: auto-expire,
        archived-at: none,
        expiry-reason: none
      }
    )
    
    (unwrap-panic (log-access record-id "SET_RETENTION" true))
    (ok true)
  )
)

(define-public (expire-record (record-id uint) (reason (string-ascii 64)))
  (match (map-get? criminal-records { record-id: record-id })
    record-data
      (begin
        (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
        (asserts! (not (is-eq (get status record-data) STATUS_EXPIRED)) ERR_RECORD_EXPIRED)
        
        (map-set criminal-records
          { record-id: record-id }
          (merge record-data {
            status: STATUS_EXPIRED,
            last-modified: stacks-block-height
          })
        )
        
        (map-set record-retention
          { record-id: record-id }
          (merge (default-to 
            { retention-period: u0, expiry-block: u0, auto-expire: false, archived-at: none, expiry-reason: none }
            (map-get? record-retention { record-id: record-id }))
            {
              archived-at: (some stacks-block-height),
              expiry-reason: (some reason)
            }
          )
        )
        
        (unwrap-panic (log-access record-id "EXPIRE" true))
        (ok true)
      )
    ERR_RECORD_NOT_FOUND
  )
)

(define-read-only (get-record-retention (record-id uint))
  (ok (map-get? record-retention { record-id: record-id }))
)

(define-read-only (check-record-expiry (record-id uint))
  (ok (is-record-expired record-id))
)
