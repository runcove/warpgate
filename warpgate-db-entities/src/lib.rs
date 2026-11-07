#![allow(non_snake_case)]

// macro list allows compile-time iteration

#[macro_export]
macro_rules! with_every_entity {
    ($callback:ident) => {
        $callback![
            AdminRole,
            ApiToken,
            CertificateCredential,
            CertificateRevocation,
            FailedLoginAttempt,
            HttpSession,
            IpBlock,
            KnownHost,
            LdapServer,
            LogEntry,
            Node,
            OtpCredential,
            Parameters,
            PasswordCredential,
            PublicKeyCredential,
            Recording,
            Role,
            SecretBackend,
            SessionApprovalRequest,
            SshClientKey,
            SsoCredential,
            Target,
            TargetGroup,
            TargetRoleAssignment,
            TargetSession,
            Ticket,
            TicketRequest,
            User,
            UserAdminRoleAssignment,
            UserLockout,
            UserRoleAssignment,
            UserSession,
        ];
    };
}

macro_rules! declare_modules {
    ($($name:ident),* $(,)?) => {
        $( pub mod $name; )*
    };
}

with_every_entity!(declare_modules);

// Not in the list above: the list drives `copy-database`, and these rows are
// transient (a session close still owed), so they are not copied.
pub mod PendingSessionClose;
