using Api.Auth;

namespace Api.Authz;

public enum StorageAction { Read, Write, List }

// The one request shape every paradigm evaluates. Resource is an object key (read/write) or a
// prefix (list).
public sealed record AuthzRequest(CallerClaims Caller, StorageAction Action, string Resource);

public sealed record AuthzDecision(bool Permit, string Reason, string Paradigm);
