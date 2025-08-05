(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_RECORD_NOT_FOUND (err u101))
(define-constant ERR_VERSION_NOT_FOUND (err u109))
(define-constant ERR_INVALID_FIELD (err u110))

(define-constant ROLE_COURT u2)
(define-constant ROLE_ADMIN u1)

(define-map authorized-users principal uint)

(define-map record-versions
  { record-id: uint, version-id: uint }
  {
    field-name: (string-ascii 32),
    old-value: (string-ascii 256),
    new-value: (string-ascii 256),
    changed-by: principal,
    changed-at: uint,
    change-reason: (string-ascii 128)
  }
)

(define-map version-metadata
  { record-id: uint }
  {
    current-version: uint,
    total-changes: uint,
    last-change-at: uint,
    created-at: uint
  }
)

(define-data-var next-version-id uint u1)

(define-private (is-authorized (user principal) (required-role uint))
  (match (map-get? authorized-users user)
    role (>= role required-role)
    false
  )
)

(define-private (increment-version (record-id uint))
  (let ((current-meta (default-to 
    { current-version: u0, total-changes: u0, last-change-at: u0, created-at: stacks-block-height }
    (map-get? version-metadata { record-id: record-id }))))
    (map-set version-metadata
      { record-id: record-id }
      (merge current-meta {
        current-version: (+ (get current-version current-meta) u1),
        total-changes: (+ (get total-changes current-meta) u1),
        last-change-at: stacks-block-height
      })
    )
    (get current-version current-meta)
  )
)

(define-public (track-field-change
  (record-id uint)
  (field-name (string-ascii 32))
  (old-value (string-ascii 256))
  (new-value (string-ascii 256))
  (reason (string-ascii 128))
)
  (let ((version-id (increment-version record-id)))
    (asserts! (is-authorized tx-sender ROLE_COURT) ERR_UNAUTHORIZED)
    (asserts! (not (is-eq old-value new-value)) ERR_INVALID_FIELD)
    
    (map-set record-versions
      { record-id: record-id, version-id: version-id }
      {
        field-name: field-name,
        old-value: old-value,
        new-value: new-value,
        changed-by: tx-sender,
        changed-at: stacks-block-height,
        change-reason: reason
      }
    )
    (ok version-id)
  )
)

(define-read-only (get-version-history (record-id uint))
  (ok (map-get? version-metadata { record-id: record-id }))
)

(define-read-only (get-specific-version (record-id uint) (version-id uint))
  (ok (map-get? record-versions { record-id: record-id, version-id: version-id }))
)

(define-read-only (verify-change-integrity (record-id uint) (version-id uint))
  (match (map-get? record-versions { record-id: record-id, version-id: version-id })
    version-data
      (ok {
        version-exists: true,
        field-modified: (get field-name version-data),
        modified-by: (get changed-by version-data),
        modified-at: (get changed-at version-data),
        has-reason: (> (len (get change-reason version-data)) u0)
      })
    (ok { version-exists: false, field-modified: "", modified-by: tx-sender, modified-at: u0, has-reason: false })
  )
)
