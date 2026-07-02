using Microsoft.EntityFrameworkCore;

namespace Api.Data;

// One row per brokered roundtrip — proves the Postgres wiring end to end. Not a
// domain model; the real audit/authorization schema arrives in sub-project 2.
public sealed class AuditEntry
{
    public int Id { get; set; }
    public DateTimeOffset At { get; set; }
    public string Subject { get; set; } = "";
    public string RoleArn { get; set; } = "";
    public string ObjectKey { get; set; } = "";
}

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<RbacUserRoleRow> RbacUserRoles => Set<RbacUserRoleRow>();
    public DbSet<RbacRolePermissionRow> RbacRolePermissions => Set<RbacRolePermissionRow>();
    public DbSet<AbacRuleRow> AbacRules => Set<AbacRuleRow>();
    public DbSet<AclEntryRow> AclEntries => Set<AclEntryRow>();
}
