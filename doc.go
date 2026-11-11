// Package auth provides storage-neutral authentication services, provider
// adapters, token utilities, guarded HTTP handlers, and credential interfaces.
//
// Hosts supply account policy, persistence, browser cookies, CSRF and abuse
// controls, email delivery, and deployment-specific wiring. The legacy Plugin,
// Store, GORMStore, and NewMemoryStore APIs do not implement the modern Service
// contracts or its transactional guarantees.
package auth
