//! Watchers offers for one existing owner event and a private Core task.
use bilibi_activity::FollowUp;
use bilibi_agent_api::{Channels, Definitions, Handler, Operation, OperationClient, DEFINITIONS};
use bilibi_authz::{OfferedCapabilities, OFFERED_CAPABILITIES};
use bilibi_database::Error;
use bilibi_events::On;
use bilibi_grid::{Field, FieldType, GridContribution, Source, TableDecl};
use bilibi_module_registry::{Contribution, Provenance};
use bilibi_party_ids::OrganisationId;
use bilibi_watchers::{Action, Trigger, ACTIONS, TRIGGERS};
use bilibi_tenancy::{ProofFuture, Scope};
use serde_json::{json, Value};

pub(crate) const MANAGE: &str = "people.claims.followup.manage";
const READ: &str = "people.claims.followup.view";
const KEY: &str = "people.claims.request.follow_up";
const TABLE: &str = "people_rule_claims";
const SOURCE_KIND: &str = "people.claims.request";
const EVENT: &str = "people/claims.request_approved";
fn access(error: bilibi_people_workforce::WorkforceError) -> Error {
    match error {
        bilibi_people_workforce::WorkforceError::Unauthorized => Error::Forbidden,
        bilibi_people_workforce::WorkforceError::NotFound => Error::NotFound,
        bilibi_people_workforce::WorkforceError::Failed(error) => error,
        other => Error::Refused(other.to_string()),
    }
}

macro_rules! provenance {
    () => {
        Provenance {
            module: crate::MODULE,
            source: file!(),
            line: line!(),
        }
    };
}

fn check<'a>(
    client: &'a dyn OperationClient,
    scope: &'a Scope,
    input: &'a Value,
) -> ProofFuture<'a, OrganisationId> {
    Box::pin(async move {
        let id = input["record_id"].as_i64().ok_or(Error::Invalid)?;
        let company: i64 = client
            .query_opt(
                "SELECT company_id FROM people_claim_submissions WHERE tenant_id=$1 AND id=$2",
                &[&scope.tenant(), &id],
            )
            .await?
            .ok_or(Error::NotFound)?
            .get(0);
        bilibi_people_workforce::authorization::authorize_company_proof(
            client, scope, company, MANAGE,
        )
        .await
        .map_err(access)?;
        bilibi_people_workforce::authorization::authorize_company_proof(
            client, scope, company, READ,
        )
        .await
        .map_err(access)?;
        bilibi_company::require_writable(client, scope, company, true)
            .await
            .map_err(|e| Error::Refused(e.to_string()))?;
        let row = client.query_opt(
            "SELECT rule_revision,status FROM people_claim_submissions WHERE tenant_id=$1 AND id=$2 AND company_id=$3 FOR UPDATE",
            &[&scope.tenant(), &id, &company],
        ).await?.ok_or(Error::NotFound)?;
        if input["expected_revision"].as_i64() != Some(row.get::<_, i64>(0)) {
            return Err(Error::Conflict);
        }
        if row.get::<_, String>(1) != "approved" {
            return Err(Error::Refused(
                "The source record is no longer approved.".into(),
            ));
        }
        OrganisationId::new(company).map_err(|_| Error::Invalid)
    })
}
static HANDLER: FollowUp = FollowUp {
    module: crate::MODULE,
    kind: SOURCE_KIND,
    check,
};
inventory::submit! { Contribution::new(DEFINITIONS, "people/claims.follow_up", provenance!(), &Definitions {
    operations: &[Operation { key: KEY, title: "Create a follow-up task", summary: "Create a private task for a staff member about this approved record.", keywords: &["follow-up", "task"], capability: MANAGE, input: FollowUp::input, output: || json!({"type":"object"}), handler: Handler::SafeWrite(&HANDLER), channels: Channels::Every, step_up: &[] }], guides: &[],
}) }
inventory::submit! { Contribution::new(OFFERED_CAPABILITIES, "watchers:people/claims", provenance!(), &OfferedCapabilities { principal: "watchers", capabilities: &[READ, MANAGE] }) }
inventory::submit! { Contribution::new(bilibi_agent_api::job::PRINCIPAL_WRITES, KEY, provenance!(), &bilibi_agent_api::job::PrincipalWrite { principals: &["watchers"] }) }
inventory::submit! { Contribution::new(TRIGGERS, EVENT, provenance!(), &Trigger { on: On { event: EVENT, versions: &[1] }, title: "A claim is approved", table: TABLE, subject: "/claim_id", logical_event: None, version: "revision" }) }
inventory::submit! { Contribution::new(ACTIONS, KEY, provenance!(), &Action { title: "Create a follow-up task", table: TABLE, subject: "record_id", version: "expected_revision", records: &[], approval_capabilities: &[bilibi_activity::MANAGE] }) }

static GRID: GridContribution = GridContribution {
    tables: &[TableDecl::new(TABLE, "Claims", READ,
        Source::tenant("SELECT id,company_id,rule_revision AS revision,status,id::text AS label,approved_amount,currency FROM people_claim_submissions WHERE tenant_id=$1 AND ($2::bigint=0 OR company_id IN (SELECT d.company_id FROM user_desks d JOIN users u ON u.tenant_id=d.tenant_id AND u.person_id=d.person_id WHERE d.tenant_id=$1 AND u.id=$2 AND u.kind='staff' AND u.deleted_at IS NULL))"), "id", &[
            Field::new("id", "ID", FieldType::Integer).protected(),
            Field::new("company_id", "Company ID", FieldType::Integer).protected(),
            Field::new("revision", "Revision", FieldType::Integer).protected(),
            Field::new("status", "Status", FieldType::String).protected(),
            Field::new("label", "Number", FieldType::String).protected(),
            Field::new("approved_amount", "Approved amount", FieldType::Decimal),
            Field::new("currency", "Currency", FieldType::String),
        ]).label_field("label").record_types(&[SOURCE_KIND])], record_fields: &[], links: &[],
};
bilibi_grid::contribute!("people/claims", "people/claims.rules", &GRID);

struct Owner;
impl bilibi_records::RecordOwner for Owner {
    fn authorize<'a>(
        &'a self,
        client: &'a dyn bilibi_tenancy::ProofClient,
        scope: &'a Scope,
        id: &'a str,
    ) -> ProofFuture<'a, bilibi_records::Access> {
        Box::pin(async move {
            let Some(id) = id.parse::<i64>().ok().filter(|id| *id > 0) else {
                return Ok(bilibi_records::Access::NotFound);
            };
            let Some(row) = client
                .query_opt(
                    "SELECT company_id FROM people_claim_submissions WHERE tenant_id=$1 AND id=$2",
                    &[&scope.tenant(), &id],
                )
                .await?
            else {
                return Ok(bilibi_records::Access::NotFound);
            };
            match bilibi_people_workforce::authorization::authorize_company_proof(
                client,
                scope,
                row.get(0),
                READ,
            )
            .await
            .map_err(access)
            {
                Ok(_) => Ok(bilibi_records::Access::Readable),
                Err(Error::Forbidden) => Ok(bilibi_records::Access::Forbidden),
                Err(Error::NotFound) => Ok(bilibi_records::Access::NotFound),
                Err(error) => Err(error),
            }
        })
    }
}
bilibi_records::declare!(
    "people/claims",
    bilibi_records::RecordKind::new(SOURCE_KIND, TABLE, &Owner).page("/people/claims/{id}")
);
