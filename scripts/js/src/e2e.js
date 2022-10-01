const fs = require('fs');
const crypto = require('crypto');

const {ApiPromise, WsProvider, Keyring} = require('@polkadot/api');
const {ContractPromise} = require('@polkadot/api-contract');
const Phala = require('@phala/sdk');
const hexToU8a = require('@polkadot/util');

const { TxQueue, checkUntil, checkUntilEq, blockBarrier, hex } = require('./utils.js');
const {stringToU8a} = require("@polkadot/util");

const CONTRACT_NAMES = [
    //['fat_badges', 'FatBadges'],
    //['easy_oracle', 'EasyOracle'],
    ['phat_rpc', 'PhatRpc'],
    //['advanced_judger', 'AdvancedJudger'],
]

function loadContract(name) {
    const wasmPath = `../../target/ink/${name}/${name}.wasm`;
    const metadataPath = `../../target/ink/${name}/metadata.json`;
    const wasm = hex(fs.readFileSync(wasmPath, 'hex'));
    const metadata = JSON.parse(fs.readFileSync(metadataPath));
    const constructor = metadata.V3.spec.constructors.find(c => c.label == 'new').selector;
    return {wasm, metadata, constructor};
}


async function getWorkerPubkey(api) {
    const workers = await api.query.phalaRegistry.workers.entries();
    console.log("${workers}");
    const worker = workers[0][0].args[0].toString();
    return worker;
}

async function setupGatekeeper(api, txpool, pair, worker) {
    if ((await api.query.phalaRegistry.gatekeeper()).length > 0) {
        return;
    }
    console.log('Gatekeeper: registering');
    await txpool.submit(
        api.tx.sudo.sudo(
            api.tx.phalaRegistry.registerGatekeeper(worker)
        ),
        pair,
    );
    await checkUntil(
        async () => (await api.query.phalaRegistry.gatekeeper()).length == 1,
        4 * 6000
    );
    console.log('Gatekeeper: added');
    await checkUntil(
        async () => (await api.query.phalaRegistry.gatekeeperMasterPubkey()).isSome,
        4 * 6000
    );
    console.log('Gatekeeper: master key ready');
}

async function deployCluster(api, txqueue, pair, worker, defaultCluster = '0x0000000000000000000000000000000000000000000000000000000000000000') {
    if ((await api.query.phalaRegistry.clusterKeys(defaultCluster)).isSome) {
        return defaultCluster;
    }
    console.log('Cluster: creating');
    // crete contract cluster and wait for the setup
    const { events } = await txqueue.submit(
        api.tx.phalaFatContracts.addCluster(
            'Public', // can be {'OnlyOwner': accountId}
            [worker]
        ),
        pair
    );
    const ev = events[1].event;
    console.assert(ev.section == 'phalaFatContracts' && ev.method == 'ClusterCreated');
    const clusterId = ev.data[0].toString();
    console.log('Cluster: created', clusterId)
    await checkUntil(
        async () => (await api.query.phalaRegistry.clusterKeys(clusterId)).isSome,
        4 * 6000
    );
    return clusterId;
}

async function deployContracts(api, txqueue, pair, artifacts, clusterId) {
    console.log('Contracts: uploading');
    // upload contracts
    const contractNames = Object.keys(artifacts);
    const { events: deployEvents } = await txqueue.submit(
        api.tx.utility.batchAll(
            Object.entries(artifacts).flatMap(([_k, v]) => [
                api.tx.phalaFatContracts.clusterUploadResource(clusterId, 'InkCode', v.wasm),
                api.tx.phalaFatContracts.instantiateContract(
                    { WasmCode: v.metadata.source.hash },
                    v.constructor,
                    hex(crypto.randomBytes(4).toString('hex')), // salt
                    clusterId,
                )
            ])
        ),
        pair
    );
    const contractIds = deployEvents
        .filter(ev => ev.event.section == 'phalaFatContracts' && ev.event.method == 'Instantiating')
        .map(ev => ev.event.data[0].toString());
    const numContracts = contractNames.length;
    console.assert(contractIds.length == numContracts, 'Incorrect length:', `${contractIds.length} vs ${numContracts}`);
    for (const [i, id] of contractIds.entries()) {
        artifacts[contractNames[i]].address = id;
    }
    await checkUntilEq(
        async () => (await api.query.phalaFatContracts.clusterContracts(clusterId))
            .filter(c => contractIds.includes(c.toString()) )
            .length,
        numContracts,
        4 * 6000
    );
    console.log('Contracts: uploaded');
    for (const [name, contract] of Object.entries(artifacts)) {
        await checkUntil(
            async () => (await api.query.phalaRegistry.contractKeys(contract.address)).isSome,
            4 * 6000
        );
        console.log('Contracts:', contract.address, name, 'key ready');
    }
    console.log('Contracts: deployed');
}

async function main() {
    const artifacts = Object.assign(
        {}, ...CONTRACT_NAMES.map(
            ([filename, name]) => ({[name]: loadContract(filename)})
        )
    );

    // connect to the chain
    const wsProvider = new WsProvider('ws://localhost:19944');
    const api = await ApiPromise.create({
        provider: wsProvider,
        types: {
            ...Phala.types,
            'NextNonceOk': {
                next_nonce: 'u32',
            },
            'RuntimeVersionOk': {
                spec_name: 'String',
                impl_name: 'String',
                authoring_version: 'u32',
                spec_version: 'u32',
                impl_version: 'u32',
                apis: 'Vec<(String, u32)>',
                transaction_version: 'u32',
                state_version: 'u32',
            },
            'GenesisHashOk': {
                genesis_hash: 'String',
            },
            'ExtraParam': {
                era: {
                    _enum: [
                        'Immortal',
                        'Mortal(u64, u64)',
                    ]
                },
                tip: 'u128',
            },
            'UnsignedExtrinsic': {
                pallet_id: 'u8',
                call_id: 'u8',
                call: 'Remark',
            },
            'Remark': {
                remark: 'String',
            }
        }
    });
    const txqueue = new TxQueue(api);

    // prepare accounts
    const keyring = new Keyring({type: 'sr25519'})
    const alice = keyring.addFromUri('//Alice')
    const bob = keyring.addFromUri('//Bob')
    const certAlice = await Phala.signCertificate({api, pair: alice});
    const certBob = await Phala.signCertificate({api, pair: bob});

    // connect to pruntime
    const pruntimeURL = 'http://localhost:18000';
    const prpc = Phala.createPruntimeApi(pruntimeURL);
    const worker = await getWorkerPubkey(api);
    const connectedWorker = hex((await prpc.getInfo({})).publicKey);
    console.log('Worker:', worker);
    console.log('Connected worker:', connectedWorker);

    // basic phala network setup
    await setupGatekeeper(api, txqueue, alice, worker);
    const clusterId = await deployCluster(api, txqueue, alice, worker);

    // contracts
    await deployContracts(api, txqueue, bob, artifacts, clusterId);

    // create Fat Contract objects
    const contracts = {};
    for (const [name, contract] of Object.entries(artifacts)) {
        const contractId = contract.address;
        const newApi = await api.clone().isReady;
        contracts[name] = new ContractPromise(
            await Phala.create({api: newApi, baseURL: pruntimeURL, contractId}),
            contract.metadata,
            contractId
        );
    }
    console.log('Fat Contract: connected');
    const { PhatRpc } = contracts;

    // set up the contracts
    const easyBadgeId = 0;
    const advBadgeId = 1;
    await txqueue.submit(
        api.tx.utility.batchAll([
            // set the api key & polkadot, kusama & khala RPC nodes
            PhatRpc.tx.setApiKey({}, ''),
            PhatRpc.tx.setChainInfo({}, 'kusama'),
        ]),
        bob,
        true,
    );

    // wait for the worker to sync to the bockchain
    await blockBarrier(api, prpc);

    // basic checks 0x76d579293581ba13623d2084925d28b632a55dcae540958d1f3680bbc786c65b
    console.log('Fat Contract: basic checks');

    const apiKey = await PhatRpc.query.getApiKey(certBob, {});
    console.log('API Key:', apiKey.output.toHuman());

    const chainPubKey = await PhatRpc.query.getChainAccountId(certBob, {}, 'kusama');
    console.log('Kusama Chain Public Key:', chainPubKey.output.toHuman());

    const rpcEndpointUrl = await PhatRpc.query.getRpcEndpoint(certBob, {}, 'kusama');
    console.log('Kusama RPC Endpoint URL:', rpcEndpointUrl.output.toHuman());

    // Get Next Nonce
    const nextNonce = await PhatRpc.query['submittableOracle::getNextNonce'](
        certBob, {},
        'kusama'
    );
    console.log(
        'Kusama Next Nonce:',
        nextNonce.result.isOk ? nextNonce.output.toHuman() : nextNonce.result.toHuman()
    );
    const nextNonceTx = nextNonce.result.isOk ? PhatRpc.registry.createType('NextNonceOk', nextNonce.output.asOk) : null
    console.log(PhatRpc.registry.createType('NextNonceOk', nextNonce.output.asOk).toHuman());

    // Get Runtime Version
    const runtimeVersion = await PhatRpc.query['submittableOracle::getRuntimeVersion'](
        certBob, {},
        'kusama'
    );
    console.log(
        'Kusama Runtime Version:',
        runtimeVersion.result.isOk ? runtimeVersion.output.toHuman() : runtimeVersion.result.toHuman()
    );
    let runtimeVersionTX = runtimeVersion.result.isOk ? PhatRpc.registry.createType('RuntimeVersionOk', runtimeVersion.output.asOk) : null
    console.log(PhatRpc.registry.createType('RuntimeVersionOk', runtimeVersion.output.asOk).toHuman());

    // Get Genesis Hash
    const genesisHash = await PhatRpc.query['submittableOracle::getGenesisHash'](
        certBob, {},
        'kusama'
    );
    console.log(
        'Kusama Genesis Hash:',
        genesisHash.result.isOk ? genesisHash.output.toHuman() : genesisHash.result.toHuman()
    );
    const genesisHashTx = genesisHash.result.isOk ? PhatRpc.registry.createType('GenesisHashOk', genesisHash.output.asOk) : null
    console.log(PhatRpc.registry.createType('GenesisHashOk', genesisHash.output.asOk).toHuman());
    let callData = PhatRpc.registry.createType('Vec<u8>', 'hi how are ya');
    const callParam = PhatRpc.registry.createType('UnsignedExtrinsic', {
        pallet_id: 0,
        call_id: 1,
        call: {
            remark: 'hi how are ya',
        }
    });
    const extraParams = PhatRpc.registry.createType('ExtraParam', {
        'era': 'Immortal',
        'tip': 0,
    });
    console.log(nextNonceTx.toHuman());
    console.log(runtimeVersionTX.toHuman());
    console.log(genesisHashTx.toHuman());
    console.log(callParam.toHuman());
    console.log(extraParams.toHuman());
    const sendTx = await PhatRpc.query['submittableOracle::createTransaction'](
        certBob, {},
        'GJPLYrZBk7qiwku23fHQUtS2wjU5PKvhSS56uL8ma6zhtBD',
        'kusama',
        nextNonceTx,
        runtimeVersionTX,
        genesisHashTx,
        callParam,
        extraParams
    );

    console.log(
        'Kusama TX hash:',
        sendTx.result.isOk ? sendTx.output.toHuman() : sendTx.result.toHuman()
    );

}

main().then(process.exit).catch(err => console.error('Crashed', err)).finally(() => process.exit(-1));