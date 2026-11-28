//! Admin-only bounded drain. The coordinator owns persistent channel/peer admission fences.
use crate::api::error::{LdkServerError, LdkServerErrorCode};
use crate::service::Context;
use ldk_node::bitcoin::Address;
use ldk_node::drain::{DrainError, DrainRequest};
use ldk_server_grpc::api::{
	BoundedDrainRequest, BoundedDrainResponse, DrainInput, GetDrainInventoryRequest,
	GetDrainInventoryResponse,
};
use std::{str::FromStr, sync::Arc};

fn refused() -> LdkServerError {
	LdkServerError::new(LdkServerErrorCode::InvalidRequestError, "Bounded drain refused")
}

fn error(error: DrainError) -> LdkServerError {
	// No address, input, credential or transaction material enters the error text.
	let reason = match error {
		DrainError::BroadcastUnavailable => "Bounded drain: enqueue unavailable",
		DrainError::NotRunning => "Bounded drain: node not running",
		DrainError::Obligations => "Bounded drain: outstanding obligations",
		DrainError::InventoryLimit => "Bounded drain: inventory limit",
		DrainError::UnsupportedInput => "Bounded drain: unsupported input",
		DrainError::InputUnavailable => "Bounded drain: input unavailable",
		DrainError::InventoryChanged => "Bounded drain: inventory changed",
		DrainError::FeeLimit => "Bounded drain: fee limit",
		DrainError::InvalidRequest => "Bounded drain: invalid request",
		DrainError::InvalidTransaction => "Bounded drain: invalid transaction",
		DrainError::Wallet(_) => "Bounded drain: wallet operation failed",
	};
	LdkServerError::new(LdkServerErrorCode::InvalidRequestError, reason)
}

fn check_node(context: &Context, expected: &str) -> Result<(), LdkServerError> {
	if expected.len() != 66 || expected != context.node.node_id().to_string() {
		return Err(refused());
	}
	Ok(())
}

pub(crate) async fn handle_get_drain_inventory(
	context: Arc<Context>, request: GetDrainInventoryRequest,
) -> Result<GetDrainInventoryResponse, LdkServerError> {
	check_node(&context, &request.expected_node_id)?;
	let inventory = context.node.drain_inventory().map_err(error)?;
	Ok(GetDrainInventoryResponse {
		node_id: request.expected_node_id,
		commitment: inventory.commitment.to_vec().into(),
		total_sat: inventory.total_sat,
		inputs: inventory
			.inputs
			.into_iter()
			.map(|input| DrainInput {
				txid: input.outpoint.txid.to_string(),
				vout: input.outpoint.vout,
				value_sat: input.value_sat,
				script_pubkey: input.script_pubkey.into_bytes().into(),
			})
			.collect(),
	})
}

pub(crate) async fn handle_bounded_drain(
	context: Arc<Context>, request: BoundedDrainRequest,
) -> Result<BoundedDrainResponse, LdkServerError> {
	check_node(&context, &request.expected_node_id)?;
	if request.destination.len() > 90 {
		return Err(refused());
	}
	let expected_commitment =
		request.expected_commitment.as_ref().try_into().map_err(|_| refused())?;
	let destination = Address::from_str(&request.destination)
		.map_err(|_| refused())?
		.require_network(context.node.config().network)
		.map_err(|_| refused())?;
	let result = context
		.node
		.bounded_drain(DrainRequest {
			expected_commitment,
			destination,
			fee_rate_sat_per_vb: request.fee_rate_sat_per_vb,
			max_fee_rate_sat_per_vb: request.max_fee_rate_sat_per_vb,
			max_total_fee_sat: request.max_total_fee_sat,
		})
		.map_err(error)?;
	Ok(BoundedDrainResponse {
		txid: result.txid.to_string(),
		fee_sat: result.fee_sat,
		output_sat: result.output_sat,
	})
}
