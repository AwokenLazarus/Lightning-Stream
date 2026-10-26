import { setupManifest } from '@start9labs/start-sdk'

// A regtest stand-in for Lightning Fork's StartOS package (id lightning-fork), for a package test only:
// its node's REST on 8080 at the container address, tls.cert at the root of the main volume and a copy alone
// in its public/ folder, as the real one (0.21.4-beta.21.1:1 and later) has them. It also runs the regtest chain node and a second node (the far end of a channel).
export const manifest = setupManifest({
  id: 'lightning-fork',
  title: 'Lightning Fork (regtest stand-in)',
  license: 'MIT',
  packageRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  upstreamRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  marketingUrl: 'https://github.com/AwokenLazarus/Lightning-Stream',
  donationUrl: null,
  description: { short: { en_US: 'Lightning Fork on regtest, for a package test' }, long: { en_US: 'A regtest stand-in for a package test. Not Lightning Fork.' } },
  volumes: ['main'],
  images: {
    lnd: { source: { dockerTag: 'lightning-fork:dev' }, arch: ['x86_64'] },
    knots: { source: { dockerTag: 'knots-blake2b:final-zmq' }, arch: ['x86_64'] },
  },
  hardwareRequirements: {},
  dependencies: {},
})
