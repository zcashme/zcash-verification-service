//! Compile-time selected chain source adapter.

use std::pin::Pin;

#[cfg(feature = "zebra-indexer")]
use anyhow::anyhow;
use anyhow::Context;
use futures_util::{stream, Stream};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{BlockId, RawTransaction, TreeState};

pub type ChainStream<T> = Pin<Box<dyn Stream<Item = anyhow::Result<T>> + Send>>;

/// The single chain client used by wallet initialization, sync, and the actor.
/// Its transport is selected at compile time by the `lwd` or `zebra-indexer`
/// Cargo feature.
pub struct ChainClient {
    #[cfg(feature = "lwd")]
    inner:
        zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<
            tonic::transport::Channel,
        >,

    #[cfg(feature = "zebra-indexer")]
    inner: ZebraRpcClient,
}

#[cfg(feature = "lwd")]
impl ChainClient {
    /// Connect to the configured lightwalletd gRPC endpoint.
    pub async fn connect(
        url: &str,
        _indexer_url: &str,
        _cookie_file: Option<&std::path::Path>,
        _network: crate::network::ZNetwork,
    ) -> anyhow::Result<Self> {
        use std::time::Duration;
        use tonic::transport::{Channel, ClientTlsConfig};
        use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

        let endpoint = Channel::from_shared(url.to_string()).context("invalid lightwalletd URL")?;
        let endpoint = if url.starts_with("https://") {
            endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .context("configuring lightwalletd TLS")?
        } else {
            endpoint
        };

        let channel = endpoint
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(true)
            .connect()
            .await
            .context("connecting to lightwalletd")?;

        Ok(Self {
            inner: CompactTxStreamerClient::new(channel),
        })
    }

    pub async fn get_latest_block(&mut self) -> anyhow::Result<BlockId> {
        use zcash_client_backend::proto::service::ChainSpec;

        self.inner
            .get_latest_block(ChainSpec {})
            .await
            .context("GetLatestBlock failed")
            .map(tonic::Response::into_inner)
    }

    pub async fn get_tree_state(&mut self, height: u64) -> anyhow::Result<TreeState> {
        self.inner
            .get_tree_state(BlockId {
                height,
                hash: vec![],
            })
            .await
            .context("GetTreeState failed")
            .map(tonic::Response::into_inner)
    }

    pub async fn get_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<ChainStream<CompactBlock>> {
        use zcash_client_backend::proto::service::BlockRange;

        let stream = self
            .inner
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: start,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: end,
                    hash: vec![],
                }),
                pool_types: vec![],
            })
            .await
            .context("GetBlockRange failed")?
            .into_inner();

        Ok(box_tonic_stream(stream))
    }

    pub async fn get_mempool_stream(&mut self) -> anyhow::Result<ChainStream<RawTransaction>> {
        let stream = self
            .inner
            .get_mempool_stream(zcash_client_backend::proto::service::Empty {})
            .await
            .context("GetMempoolStream failed")?
            .into_inner();
        Ok(box_tonic_stream(stream))
    }

    pub async fn send_transaction(&mut self, data: Vec<u8>) -> anyhow::Result<(i32, String)> {
        let response = self
            .inner
            .send_transaction(RawTransaction { data, height: 0 })
            .await
            .context("SendTransaction failed")?
            .into_inner();
        Ok((response.error_code, response.error_message))
    }
}

#[cfg(feature = "zebra-indexer")]
impl ChainClient {
    /// Connect to Zebra's local JSON-RPC endpoint.
    pub async fn connect(
        url: &str,
        indexer_url: &str,
        cookie_file: Option<&std::path::Path>,
        network: crate::network::ZNetwork,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: ZebraRpcClient::connect(url, indexer_url, cookie_file, network).await?,
        })
    }

    pub async fn get_latest_block(&mut self) -> anyhow::Result<BlockId> {
        let height: u64 = self
            .inner
            .call("getblockcount", serde_json::json!([]))
            .await?;
        Ok(BlockId {
            height,
            hash: vec![],
        })
    }

    pub async fn get_tree_state(&mut self, height: u64) -> anyhow::Result<TreeState> {
        self.inner.get_tree_state(height).await
    }

    pub async fn get_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<ChainStream<CompactBlock>> {
        let rpc = self.inner.clone();
        let network = self.inner.network;
        let blocks = stream::try_unfold(
            (rpc, network, start),
            move |(rpc, network, height)| async move {
                if height > end {
                    return Ok(None);
                }
                let block = rpc.get_compact_block(height, network).await?;
                let next_height = height.saturating_add(1);
                Ok(Some((block, (rpc, network, next_height))))
            },
        );
        Ok(Box::pin(blocks))
    }

    /// Watch Zebra Indexer mempool events and resolve added transaction IDs
    /// through JSON-RPC. The stream ends when the chain tip changes, matching
    /// the actor's existing sync/reopen loop.
    pub async fn get_mempool_stream(&mut self) -> anyhow::Result<ChainStream<RawTransaction>> {
        let rpc = self.inner.clone();
        let tip_height: u64 = rpc.call("getblockcount", serde_json::json!([])).await?;
        let tip_hash: String = rpc
            .call("getblockhash", serde_json::json!([tip_height]))
            .await?;
        let observed_tip = (
            u32::try_from(tip_height).context("Zebra tip height exceeds Indexer range")?,
            hex::decode(tip_hash).context("decoding Zebra tip hash")?,
        );
        let mut indexer = self.inner.indexer.clone();
        let mempool = indexer
            .mempool_change(zebra_indexer_proto::Empty {})
            .await
            .context("opening Zebra Indexer mempool stream")?
            .into_inner();
        let tip_changes = indexer
            .chain_tip_change(zebra_indexer_proto::Empty {})
            .await
            .context("opening Zebra Indexer chain-tip stream")?
            .into_inner();

        // Indexer streams are change-only. Snapshot once after subscribing so
        // transactions already present in the mempool are replayed on restart;
        // the set suppresses duplicate Added notifications racing the snapshot.
        let initial: Vec<String> = rpc.call("getrawmempool", serde_json::json!([])).await?;
        let known = initial.iter().cloned().collect();
        let state = ZebraMempoolState {
            rpc,
            mempool,
            tip_changes,
            pending: initial.into(),
            known,
            observed_tip,
        };
        let stream = stream::unfold(state, |mut state| async move {
            loop {
                if let Some(txid) = state.pending.pop_front() {
                    let result = async {
                        let encoded: String = state
                            .rpc
                            .call("getrawtransaction", serde_json::json!([txid, 0]))
                            .await?;
                        Ok::<_, anyhow::Error>(RawTransaction {
                            data: hex::decode(encoded)
                                .context("decoding raw mempool transaction")?,
                            height: 0,
                        })
                    }
                    .await;
                    return Some((result, state));
                }

                tokio::select! {
                    tip = state.tip_changes.message() => match tip {
                        Ok(Some(tip))
                            if tip.height != state.observed_tip.0
                                || tip.hash.as_slice() != state.observed_tip.1.as_slice() => return None,
                        Ok(Some(_)) => continue,
                        Ok(None) => return Some((Err(anyhow!("Zebra chain-tip stream closed")), state)),
                        Err(error) => return Some((Err(error.into()), state)),
                    },
                    change = state.mempool.message() => match change {
                        Ok(Some(change)) => match change.kind() {
                            Some(zebra_indexer_proto::MempoolChangeKind::Added) => {
                                let Some(txid) = change.tx_hash_display_order() else {
                                    return Some((Err(anyhow!("Zebra Indexer sent an invalid transaction hash")), state));
                                };
                                let txid = hex::encode(txid);
                                if state.known.insert(txid.clone()) {
                                    state.pending.push_back(txid);
                                }
                            }
                            Some(zebra_indexer_proto::MempoolChangeKind::Invalidated) => {
                                if let Some(txid) = change.tx_hash_display_order() {
                                    state.known.remove(&hex::encode(txid));
                                }
                            }
                            Some(zebra_indexer_proto::MempoolChangeKind::Mined) => return None,
                            None => tracing::warn!(change_type = change.change_type, "ignoring unknown Zebra mempool change"),
                        },
                        Ok(None) => return Some((Err(anyhow!("Zebra mempool stream closed")), state)),
                        Err(error) => return Some((Err(error.into()), state)),
                    }
                }
            }
        });
        Ok(Box::pin(stream))
    }

    pub async fn send_transaction(&mut self, data: Vec<u8>) -> anyhow::Result<(i32, String)> {
        let encoded = hex::encode(data);
        match self
            .inner
            .call::<String>("sendrawtransaction", serde_json::json!([encoded]))
            .await
        {
            Ok(txid) => Ok((0, txid)),
            Err(error) => Ok((1, error.to_string())),
        }
    }
}

#[cfg(feature = "lwd")]
fn box_tonic_stream<T: Send + 'static>(stream: tonic::codec::Streaming<T>) -> ChainStream<T> {
    Box::pin(stream::unfold(Some(stream), |state| async move {
        let mut stream = state?;
        match stream.message().await {
            Ok(Some(item)) => Some((Ok(item), Some(stream))),
            Ok(None) => None,
            Err(error) => Some((Err(error.into()), None)),
        }
    }))
}

#[cfg(feature = "zebra-indexer")]
#[derive(Clone)]
struct ZebraRpcClient {
    client: reqwest::Client,
    endpoint: String,
    username: Option<String>,
    password: Option<String>,
    cookie_file: Option<std::path::PathBuf>,
    network: crate::network::ZNetwork,
    indexer: zebra_indexer_proto::ZebraClient,
}

#[cfg(feature = "zebra-indexer")]
struct ZebraMempoolState {
    rpc: ZebraRpcClient,
    mempool: tonic::codec::Streaming<zebra_indexer_proto::MempoolChangeMessage>,
    tip_changes: tonic::codec::Streaming<zebra_indexer_proto::BlockHashAndHeight>,
    pending: std::collections::VecDeque<String>,
    known: std::collections::HashSet<String>,
    observed_tip: (u32, Vec<u8>),
}

#[cfg(feature = "zebra-indexer")]
impl ZebraRpcClient {
    async fn connect(
        url: &str,
        indexer_url: &str,
        cookie_file: Option<&std::path::Path>,
        network: crate::network::ZNetwork,
    ) -> anyhow::Result<Self> {
        let mut endpoint = reqwest::Url::parse(url).context("invalid Zebra JSON-RPC URL")?;
        if endpoint.scheme() != "http" {
            anyhow::bail!("Zebra JSON-RPC URL must use http for the local daemon");
        }
        let username = (!endpoint.username().is_empty()).then(|| endpoint.username().to_owned());
        let password = endpoint.password().map(str::to_owned);
        if cookie_file.is_some() && username.is_some() {
            anyhow::bail!(
                "configure Zebra RPC auth with either --zebra-cookie-file or URL credentials"
            );
        }
        endpoint
            .set_username("")
            .map_err(|_| anyhow!("invalid username in Zebra JSON-RPC URL"))?;
        endpoint
            .set_password(None)
            .map_err(|_| anyhow!("invalid password in Zebra JSON-RPC URL"))?;

        let indexer = zebra_indexer_proto::ZebraClient::connect(indexer_url.to_owned())
            .await
            .context("connecting to Zebra Indexer gRPC")?;

        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("building Zebra JSON-RPC HTTP client")?,
            endpoint: endpoint.to_string(),
            username,
            password,
            cookie_file: cookie_file.map(std::path::Path::to_path_buf),
            network,
            indexer,
        })
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<T> {
        let mut request = self.client.post(&self.endpoint).json(&serde_json::json!({
            "jsonrpc": "1.0",
            "id": "zfa-backend",
            "method": method,
            "params": params,
        }));
        if let Some(cookie_file) = &self.cookie_file {
            let cookie = tokio::fs::read_to_string(cookie_file)
                .await
                .with_context(|| format!("reading Zebra RPC cookie {}", cookie_file.display()))?;
            let (username, password) = cookie
                .trim()
                .split_once(':')
                .ok_or_else(|| anyhow!("invalid Zebra RPC cookie format"))?;
            request = request.basic_auth(username, Some(password));
        } else if let Some(username) = &self.username {
            request = request.basic_auth(username, self.password.as_ref());
        }
        let response: serde_json::Value = request
            .send()
            .await
            .with_context(|| format!("calling Zebra RPC {method}"))?
            .error_for_status()
            .with_context(|| format!("Zebra RPC {method} HTTP response"))?
            .json()
            .await
            .with_context(|| format!("decoding Zebra RPC {method} response"))?;

        if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
            let message = error["message"]
                .as_str()
                .unwrap_or("unknown JSON-RPC error");
            anyhow::bail!("Zebra RPC {method}: {message}");
        }
        let result = response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("Zebra RPC {method} response omitted result"))?;
        serde_json::from_value(result)
            .with_context(|| format!("decoding Zebra RPC {method} result"))
    }

    async fn get_tree_state(&self, height: u64) -> anyhow::Result<TreeState> {
        let response: serde_json::Value = self
            .call("z_gettreestate", serde_json::json!([height.to_string()]))
            .await
            .context("z_gettreestate failed")?;

        let final_tree_state = |pool: &str| -> anyhow::Result<String> {
            response[pool]["commitments"]["finalState"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("z_gettreestate response missing {pool} finalState"))
        };

        Ok(TreeState {
            network: self.network.name().to_owned(),
            height: response["height"].as_u64().unwrap_or(height),
            hash: response["hash"].as_str().unwrap_or_default().to_owned(),
            time: response["time"].as_u64().unwrap_or_default() as u32,
            sapling_tree: final_tree_state("sapling")?,
            orchard_tree: final_tree_state("orchard")?,
            ironwood_tree: response["ironwood"]["commitments"]["finalState"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        })
    }

    async fn get_compact_block(
        &self,
        height: u64,
        network: crate::network::ZNetwork,
    ) -> anyhow::Result<CompactBlock> {
        use std::io::Cursor;
        use zcash_client_backend::proto::compact_formats::{
            ChainMetadata, CompactOrchardAction, CompactSaplingSpend, CompactTx,
        };

        let encoded: String = self
            .call("getblock", serde_json::json!([height.to_string(), 0]))
            .await
            .with_context(|| format!("fetching Zebra block {height}"))?;
        let bytes = hex::decode(encoded).context("decoding Zebra block hex")?;
        let block = zcash_primitives::block::Block::read(Cursor::new(bytes), &network)
            .with_context(|| format!("parsing Zebra block {height}"))?;
        let header = block.header();
        let mut compact_txs = Vec::with_capacity(block.vtx().len());

        for (index, tx) in block.vtx().iter().enumerate() {
            let mut compact_tx = CompactTx {
                index: index as u64,
                txid: tx.txid().as_ref().to_vec(),
                ..Default::default()
            };
            if let Some(bundle) = tx.sapling_bundle() {
                compact_tx.spends = bundle
                    .shielded_spends()
                    .iter()
                    .map(|spend| CompactSaplingSpend {
                        nf: spend.nullifier().to_vec(),
                    })
                    .collect();
                compact_tx.outputs = bundle.shielded_outputs().iter().map(Into::into).collect();
            }
            if let Some(bundle) = tx.orchard_bundle() {
                compact_tx.actions = bundle
                    .actions()
                    .iter()
                    .map(|action| CompactOrchardAction {
                        nullifier: action.nullifier().to_bytes().to_vec(),
                        cmx: action.cmx().to_bytes().to_vec(),
                        ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
                        ciphertext: action.encrypted_note().enc_ciphertext[..52].to_vec(),
                    })
                    .collect();
            }
            if let Some(bundle) = tx.ironwood_bundle() {
                compact_tx.ironwood_actions = bundle
                    .actions()
                    .iter()
                    .map(|action| CompactOrchardAction {
                        nullifier: action.nullifier().to_bytes().to_vec(),
                        cmx: action.cmx().to_bytes().to_vec(),
                        ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
                        ciphertext: action.encrypted_note().enc_ciphertext[..52].to_vec(),
                    })
                    .collect();
            }
            compact_txs.push(compact_tx);
        }

        // The compact wallet scanner needs the note commitment tree sizes at
        // the end of each block. Zebra's raw block RPC omits them, so obtain
        // them from the same node's tree-state RPC.
        let tree_state = self.get_tree_state(height).await?;
        let chain_metadata = ChainMetadata {
            sapling_commitment_tree_size: tree_state
                .sapling_tree()?
                .size()
                .try_into()
                .context("Sapling tree size exceeds compact block limit")?,
            orchard_commitment_tree_size: tree_state
                .orchard_tree()?
                .size()
                .try_into()
                .context("Orchard tree size exceeds compact block limit")?,
            ironwood_commitment_tree_size: tree_state
                .ironwood_tree()?
                .size()
                .try_into()
                .context("Ironwood tree size exceeds compact block limit")?,
        };

        Ok(CompactBlock {
            height,
            hash: header.hash().0.to_vec(),
            prev_hash: header.prev_block.0.to_vec(),
            time: header.time,
            header: vec![],
            vtx: compact_txs,
            chain_metadata: Some(chain_metadata),
        })
    }
}
