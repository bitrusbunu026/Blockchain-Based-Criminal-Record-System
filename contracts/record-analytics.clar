(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_PERIOD (err u111))

(define-constant ROLE_ADMIN u1)
(define-constant ROLE_COURT u2)

(define-map authorized-users principal uint)

(define-map system-metrics
  { metric-type: (string-ascii 32) }
  {
    total-count: uint,
    daily-count: uint,
    weekly-count: uint,
    monthly-count: uint,
    last-updated: uint
  }
)

(define-map user-activity
  { user: principal }
  {
    total-actions: uint,
    last-active: uint,
    records-created: uint,
    records-accessed: uint,
    first-login: uint
  }
)

(define-map daily-stats
  { date-block: uint }
  {
    records-created: uint,
    records-accessed: uint,
    unique-users: uint,
    total-actions: uint
  }
)

(define-data-var current-day-block uint u0)

(define-private (is-authorized (user principal) (required-role uint))
  (match (map-get? authorized-users user)
    role (>= role required-role)
    false
  )
)

(define-private (get-day-block)
  (/ stacks-block-height u144)
)

(define-private (update-metric (metric-type (string-ascii 32)) (increment uint))
  (let ((current-day (get-day-block))
        (current-metrics (default-to 
          { total-count: u0, daily-count: u0, weekly-count: u0, monthly-count: u0, last-updated: u0 }
          (map-get? system-metrics { metric-type: metric-type }))))
    (map-set system-metrics
      { metric-type: metric-type }
      (merge current-metrics {
        total-count: (+ (get total-count current-metrics) increment),
        daily-count: (if (is-eq current-day (/ (get last-updated current-metrics) u144))
          (+ (get daily-count current-metrics) increment)
          increment),
        last-updated: stacks-block-height
      })
    )
  )
)

(define-public (track-record-creation)
  (begin
    (update-metric "RECORD_CREATED" u1)
    (update-user-activity "records-created")
    (update-daily-stats "records-created")
    (ok true)
  )
)

(define-public (track-record-access)
  (begin
    (update-metric "RECORD_ACCESSED" u1)
    (update-user-activity "records-accessed")
    (update-daily-stats "records-accessed")
    (ok true)
  )
)

(define-private (update-user-activity (action-type (string-ascii 32)))
  (let ((current-activity (default-to 
    { total-actions: u0, last-active: u0, records-created: u0, records-accessed: u0, first-login: stacks-block-height }
    (map-get? user-activity { user: tx-sender }))))
    (map-set user-activity
      { user: tx-sender }
      (merge current-activity {
        total-actions: (+ (get total-actions current-activity) u1),
        last-active: stacks-block-height,
        records-created: (if (is-eq action-type "records-created")
          (+ (get records-created current-activity) u1)
          (get records-created current-activity)),
        records-accessed: (if (is-eq action-type "records-accessed")
          (+ (get records-accessed current-activity) u1)
          (get records-accessed current-activity))
      })
    )
  )
)

(define-private (update-daily-stats (stat-type (string-ascii 32)))
  (let ((current-day (get-day-block))
        (current-stats (default-to 
          { records-created: u0, records-accessed: u0, unique-users: u0, total-actions: u0 }
          (map-get? daily-stats { date-block: current-day }))))
    (map-set daily-stats
      { date-block: current-day }
      (merge current-stats {
        records-created: (if (is-eq stat-type "records-created")
          (+ (get records-created current-stats) u1)
          (get records-created current-stats)),
        records-accessed: (if (is-eq stat-type "records-accessed")
          (+ (get records-accessed current-stats) u1)
          (get records-accessed current-stats)),
        total-actions: (+ (get total-actions current-stats) u1)
      })
    )
  )
)

(define-read-only (get-system-metrics (metric-type (string-ascii 32)))
  (ok (map-get? system-metrics { metric-type: metric-type }))
)

(define-read-only (get-user-activity (user principal))
  (ok (map-get? user-activity { user: user }))
)

(define-read-only (get-daily-stats (date-block uint))
  (ok (map-get? daily-stats { date-block: date-block }))
)

(define-read-only (get-system-overview)
  (let ((created-metrics (default-to 
    { total-count: u0, daily-count: u0, weekly-count: u0, monthly-count: u0, last-updated: u0 }
    (map-get? system-metrics { metric-type: "RECORD_CREATED" })))
    (accessed-metrics (default-to 
      { total-count: u0, daily-count: u0, weekly-count: u0, monthly-count: u0, last-updated: u0 }
      (map-get? system-metrics { metric-type: "RECORD_ACCESSED" }))))
    (ok {
      total-records-created: (get total-count created-metrics),
      total-records-accessed: (get total-count accessed-metrics),
      daily-creations: (get daily-count created-metrics),
      daily-accesses: (get daily-count accessed-metrics),
      system-active: (or (> (get last-updated created-metrics) u0) (> (get last-updated accessed-metrics) u0))
    })
  )
)
