//! A real approved claim for the mounted follow-up rule proof, never a payment.
use bilibi_authz::grants::{Direct, Grants};
use bilibi_database::{Error, Result};
use bilibi_people_claims::{Approval, Claims, NewCategory, NewClaimType, NewPolicy, NewRequest};
use bilibi_tenancy::Authentication;
use jiff::civil::date;
use rust_decimal::Decimal;
fn kept<T>(value: std::result::Result<T, bilibi_people_claims::ClaimsError>) -> Result<T> {
    value.map_err(|error| {
        eprintln!("claim rule source: {error}");
        Error::Invalid
    })
}
async fn prepare(ctx: &mut crate::Context) -> Result<()> {
    let claims = ctx.services.get::<Claims>(bilibi_people_claims::SERVICE)?;
    ctx.services
        .get::<Grants>("base/authz.grants")?
        .set_direct(
            &ctx.admin,
            3,
            bilibi_people_claims::SUBMIT,
            Some(Direct::Allow(bilibi_authz::Reach::All)),
        )
        .await?;
    let client = ctx.db.get().await?;
    let staff = ctx
        .services
        .get::<Authentication>("base/tenancy.authentication")?
        .authenticate(&**client, 1, 3, "claim-rule-source".into())
        .await?;
    drop(client);
    let category = kept(
        claims
            .create_category(
                &ctx.manager,
                1,
                &NewCategory {
                    code: "rule_followup".into(),
                    name: "Follow-up proof".into(),
                },
            )
            .await,
    )?;
    let kind = kept(
        claims
            .create_claim_type(
                &ctx.manager,
                1,
                &NewClaimType {
                    category_id: category.id,
                    code: "rule_followup".into(),
                    name: "Follow-up proof".into(),
                    receipt_requirement: "never".into(),
                    eligibility: None,
                },
            )
            .await,
    )?;
    kept(
        claims
            .create_policy(
                &ctx.manager,
                1,
                &NewPolicy {
                    claim_type_id: kind.id,
                    effective_from: date(2026, 1, 1),
                    effective_to: None,
                    currency: "MYR".into(),
                    per_claim_limit: None,
                    monthly_limit: None,
                    yearly_limit: None,
                    receipt_threshold: None,
                },
            )
            .await,
    )?;
    let claim = kept(
        claims
            .submit_request(
                &staff,
                1,
                &NewRequest {
                    claim_type_id: kind.id,
                    incurred_on: date(2026, 11, 1),
                    amount: Decimal::from(10),
                    currency: "MYR".into(),
                    description: Some("Follow-up proof".into()),
                    receipt_number: None,
                    confirm_duplicate: false,
                },
            )
            .await,
    )?;
    kept(
        claims
            .approve_request(
                &ctx.manager,
                1,
                claim.id,
                &Approval {
                    approved_amount: Some(Decimal::from(10)),
                    decision_reason: Some("Follow-up proof".into()),
                },
            )
            .await,
    )?;
    Ok(())
}
walkthrough_command!("rules-source", |url, _argument| async move {
    let mut ctx = crate::workforce::prepare(url).await?;
    bilibi_walkthrough_fixture::set_instance_role(&ctx.db, "development").await?;
    let modules = bilibi_module_registry::discover()?;
    bilibi_database::seeds::run(&ctx.db, &modules, ctx.services.catalog()?, &ctx.services).await?;
    let claims = ctx.services.get::<Claims>(bilibi_people_claims::SERVICE)?;
    kept(
        claims
            .put_currencies(&ctx.manager, 1, &["MYR".into()])
            .await,
    )?;
    prepare(&mut ctx).await
});
