"""Action -> capability reference data.

Rule A asks a question that spans two vocabularies:

    Privilege utilisation = observed relevant actions / granted relevant capabilities

The *granted* side is written in policy language (``s3:*``, ``AdministratorAccess``)
and the *observed* side arrives as concrete API calls (``s3:GetObject``,
``repo.clone``). Neither can be compared to the other directly. This module is
the translation table between them.

It is deliberately **data, not logic**. If this mapping lived inside the Phase 2
rule function, the rule could not be tested without also testing the mapping,
and a fixture could not reveal that a permission had been silently
unclassifiable. Keeping it here means:

* Phase 2's ``utilization.py`` is a pure set computation over two frozensets.
* ``test_capabilities`` can assert that every permission appearing in
  ``data/*.json`` classifies to something other than ``UNKNOWN`` -- so a fixture
  author who invents a permission name finds out immediately, rather than
  quietly shrinking the denominator and inflating the utilisation ratio.

The granularity is coarse and intentionally so. A reviewer reasons about "can
read S3", not about which of forty read APIs was called. Coarse capabilities
also make the ratio stable: adding ``s3:GetObjectVersion`` upstream does not
move anybody's utilisation number.
"""

from __future__ import annotations

from app.core.enums import Capability

__all__ = [
    "ACTION_TO_CAPABILITIES",
    "POLICY_TO_CAPABILITIES",
    "capabilities_for_permissions",
    "capabilities_for_actions",
    "classify_permission",
]


# --------------------------------------------------------------------------- #
# Observed side: a concrete action -> what it achieved
# --------------------------------------------------------------------------- #

ACTION_TO_CAPABILITIES: dict[str, frozenset[Capability]] = {
    # --- AWS S3 ----------------------------------------------------------- #
    "s3:ListBucket": frozenset({Capability.S3_READ}),
    "s3:ListAllMyBuckets": frozenset({Capability.S3_READ}),
    "s3:GetObject": frozenset({Capability.S3_READ}),
    "s3:GetObjectVersion": frozenset({Capability.S3_READ}),
    "s3:PutObject": frozenset({Capability.S3_WRITE}),
    "s3:DeleteObject": frozenset({Capability.S3_DELETE}),
    "s3:PutBucketPolicy": frozenset({Capability.S3_WRITE, Capability.IAM_WRITE}),
    # --- AWS EC2 ---------------------------------------------------------- #
    "ec2:DescribeInstances": frozenset({Capability.EC2_READ}),
    "ec2:DescribeSecurityGroups": frozenset({Capability.EC2_READ}),
    "ec2:DescribeVolumes": frozenset({Capability.EC2_READ}),
    "ec2:RunInstances": frozenset({Capability.EC2_WRITE}),
    "ec2:StartInstances": frozenset({Capability.EC2_WRITE}),
    "ec2:StopInstances": frozenset({Capability.EC2_WRITE}),
    "ec2:TerminateInstances": frozenset({Capability.EC2_WRITE}),
    "ec2:ModifyInstanceAttribute": frozenset({Capability.EC2_WRITE}),
    # --- AWS IAM ---------------------------------------------------------- #
    "iam:GetRole": frozenset({Capability.IAM_READ}),
    "iam:ListRoles": frozenset({Capability.IAM_READ}),
    "iam:ListAttachedRolePolicies": frozenset({Capability.IAM_READ}),
    "iam:CreateRole": frozenset({Capability.IAM_WRITE}),
    "iam:AttachRolePolicy": frozenset({Capability.IAM_WRITE}),
    "iam:PutRolePolicy": frozenset({Capability.IAM_WRITE}),
    "iam:CreateAccessKey": frozenset({Capability.IAM_WRITE}),
    # --- AWS KMS ---------------------------------------------------------- #
    "kms:DescribeKey": frozenset({Capability.KMS_READ}),
    "kms:Decrypt": frozenset({Capability.KMS_READ}),
    "kms:Encrypt": frozenset({Capability.KMS_WRITE}),
    "kms:CreateKey": frozenset({Capability.KMS_WRITE}),
    # --- AWS CloudWatch Logs ---------------------------------------------- #
    "logs:DescribeLogGroups": frozenset({Capability.LOGS_READ}),
    "logs:GetLogEvents": frozenset({Capability.LOGS_READ}),
    "logs:FilterLogEvents": frozenset({Capability.LOGS_READ}),
    "logs:PutLogEvents": frozenset({Capability.LOGS_WRITE}),
    # --- AWS STS / Cost Explorer ------------------------------------------ #
    "sts:AssumeRole": frozenset({Capability.STS_ASSUME_ROLE}),
    "sts:GetCallerIdentity": frozenset(),
    "ce:GetCostAndUsage": frozenset({Capability.FINANCE_READ}),
    # --- GitHub ----------------------------------------------------------- #
    "repo.access": frozenset({Capability.REPO_READ}),
    "repo.clone": frozenset({Capability.REPO_READ}),
    "repo.read": frozenset({Capability.REPO_READ}),
    "git.fetch": frozenset({Capability.REPO_READ}),
    "pull_request.read": frozenset({Capability.REPO_READ}),
    "git.push": frozenset({Capability.REPO_WRITE}),
    "pull_request.create": frozenset({Capability.REPO_WRITE}),
    "pull_request.merge": frozenset({Capability.REPO_WRITE}),
    "actions.workflow_run": frozenset({Capability.REPO_WRITE}),
    "repo.create": frozenset({Capability.REPO_ADMIN}),
    "repo.destroy": frozenset({Capability.REPO_ADMIN}),
    "repo.set_default_branch": frozenset({Capability.REPO_ADMIN}),
    "secrets.read": frozenset({Capability.REPO_ADMIN}),
    "org.add_member": frozenset({Capability.ORG_ADMIN}),
    "org.remove_member": frozenset({Capability.ORG_ADMIN}),
    # --- Finance application ---------------------------------------------- #
    "payments:ApproveTransfer": frozenset({Capability.FINANCE_APPROVE}),
    "payments:ViewTransfer": frozenset({Capability.FINANCE_READ}),
}


# --------------------------------------------------------------------------- #
# Granted side: a policy or role name -> what it confers
# --------------------------------------------------------------------------- #

#: Capabilities conferred by well-known managed policies. These are named
#: directly rather than expanded from a permission list because real managed
#: policies contain hundreds of actions and the fixture only lists a sample.
POLICY_TO_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "AdministratorAccess": frozenset(
        {
            Capability.S3_READ,
            Capability.S3_WRITE,
            Capability.S3_DELETE,
            Capability.EC2_READ,
            Capability.EC2_WRITE,
            Capability.IAM_READ,
            Capability.IAM_WRITE,
            Capability.KMS_READ,
            Capability.KMS_WRITE,
            Capability.LOGS_READ,
            Capability.LOGS_WRITE,
            Capability.STS_ASSUME_ROLE,
            Capability.FINANCE_READ,
        }
    ),
    "PowerUserAccess": frozenset(
        {
            Capability.S3_READ,
            Capability.S3_WRITE,
            Capability.S3_DELETE,
            Capability.EC2_READ,
            Capability.EC2_WRITE,
            Capability.KMS_READ,
            Capability.KMS_WRITE,
            Capability.LOGS_READ,
            Capability.LOGS_WRITE,
            Capability.STS_ASSUME_ROLE,
        }
    ),
    "FinanceReadOnlyAccess": frozenset(
        {Capability.S3_READ, Capability.FINANCE_READ}
    ),
    "SupportReadOnlyAccess": frozenset(
        {Capability.S3_READ, Capability.LOGS_READ, Capability.EC2_READ}
    ),
    "break-glass-emergency-admin": frozenset(
        {
            Capability.S3_READ,
            Capability.S3_WRITE,
            Capability.S3_DELETE,
            Capability.EC2_READ,
            Capability.EC2_WRITE,
            Capability.IAM_READ,
            Capability.IAM_WRITE,
            Capability.KMS_READ,
            Capability.KMS_WRITE,
            Capability.LOGS_READ,
            Capability.LOGS_WRITE,
            Capability.STS_ASSUME_ROLE,
        }
    ),
    "disaster-recovery-operator": frozenset(
        {
            Capability.EC2_READ,
            Capability.EC2_WRITE,
            Capability.S3_READ,
            Capability.S3_WRITE,
            Capability.KMS_READ,
        }
    ),
    "TreasuryPaymentApprover": frozenset(
        {Capability.FINANCE_APPROVE, Capability.FINANCE_READ, Capability.S3_READ}
    ),
    # GitHub role strings
    "repo:read": frozenset({Capability.REPO_READ}),
    "repo:write": frozenset({Capability.REPO_READ, Capability.REPO_WRITE}),
    "repo:admin": frozenset(
        {Capability.REPO_READ, Capability.REPO_WRITE, Capability.REPO_ADMIN}
    ),
    "org:admin": frozenset(
        {
            Capability.REPO_READ,
            Capability.REPO_WRITE,
            Capability.REPO_ADMIN,
            Capability.ORG_ADMIN,
        }
    ),
}


def _capabilities_for_wildcard(pattern: str) -> frozenset[Capability]:
    """Expand ``s3:*`` into every capability any ``s3:`` action maps to.

    Derived from :data:`ACTION_TO_CAPABILITIES` rather than written out by hand,
    so adding a new S3 action cannot leave ``s3:*`` stale.
    """
    prefix = pattern[:-1]  # drop the '*'
    expanded: set[Capability] = set()
    for action, caps in ACTION_TO_CAPABILITIES.items():
        if action.startswith(prefix):
            expanded |= caps
    return frozenset(expanded)


def classify_permission(permission: str) -> frozenset[Capability]:
    """Classify a single granted permission string.

    Returns an empty set for permissions that grant nothing observable (for
    example ``sts:GetCallerIdentity``, which only reports who you already are).
    Returns ``{UNKNOWN}`` for anything unrecognised, so that an unclassifiable
    permission is *visible* rather than silently absent -- see the module
    docstring for why that matters to the utilisation ratio.
    """
    if permission in ACTION_TO_CAPABILITIES:
        return ACTION_TO_CAPABILITIES[permission]
    if permission in POLICY_TO_CAPABILITIES:
        return POLICY_TO_CAPABILITIES[permission]
    if permission.endswith(":*"):
        expanded = _capabilities_for_wildcard(permission)
        return expanded if expanded else frozenset({Capability.UNKNOWN})
    if permission == "*":
        return frozenset(Capability)
    return frozenset({Capability.UNKNOWN})


def capabilities_for_permissions(permissions: list[str]) -> frozenset[Capability]:
    """Collapse a granted permission list into the set of capabilities it confers."""
    granted: set[Capability] = set()
    for permission in permissions:
        granted |= classify_permission(permission)
    return frozenset(granted)


def capabilities_for_actions(actions: list[str]) -> frozenset[Capability]:
    """Collapse observed actions into the set of capabilities actually exercised.

    This mirrors :func:`classify_permission` deliberately, and the symmetry is
    load-bearing. The two sides answer the same question in opposite directions,
    so a vocabulary gap must be visible on both:

    * On the granted side an unclassifiable permission shrinks the *denominator*,
      which inflates the utilisation ratio and hides privilege.
    * On the observed side an unclassifiable action shrinks the *numerator*,
      which deflates the ratio and manufactures a low-usage finding against a
      real person -- the false positive Rule 6 exists to prevent.

    So an action absent from :data:`ACTION_TO_CAPABILITIES` yields
    ``{UNKNOWN}``, not silence.

    Note what this is *not*: an empty set still means something precise, and the
    two must stay distinguishable. ``sts:GetCallerIdentity`` is deliberately
    mapped to ``frozenset()`` because it is a *known* action that confers no
    capability -- it only reports who you already are. "Known to achieve
    nothing" and "not known at all" are different facts about a person's
    evidence, and collapsing them into one return value would lose the
    distinction the reviewer needs. ``tests/test_capabilities.py`` holds the
    line: no action in the fixture set may reach the ``UNKNOWN`` fallback, so
    the vocabulary cannot drift away from the data unnoticed.
    """
    observed: set[Capability] = set()
    for action in actions:
        observed |= ACTION_TO_CAPABILITIES.get(action, frozenset({Capability.UNKNOWN}))
    return frozenset(observed)
