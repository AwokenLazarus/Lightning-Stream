import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'
import { IMAGES } from '../spec'

// The images are the local, multi-platform tags scripts/oci_build.sh --load makes (one image set with the
// Umbrel apps and xbt-compute); `start-cli s9pk pack` takes each architecture from the local Docker. They are
// never pulled or pushed. StartOS runs x86_64 and aarch64 (the images also exist for arm/v7).

export const manifest = setupManifest({
  id: 'xbt-agent-wallet',
  title: 'XBT Agent Wallet',
  license: 'MIT OR Apache-2.0',
  packageRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  upstreamRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  marketingUrl: 'https://github.com/AwokenLazarus/Lightning-Stream',
  donationUrl: null,
  description: { short, long },
  volumes: ['main', 'startos'],
  images: {
    init: { source: { dockerTag: IMAGES.init }, arch: ['x86_64', 'aarch64'] },
    signer: { source: { dockerTag: IMAGES.signer }, arch: ['x86_64', 'aarch64'] },
    witness: { source: { dockerTag: IMAGES.witness }, arch: ['x86_64', 'aarch64'] },
    mcp: { source: { dockerTag: IMAGES.mcp }, arch: ['x86_64', 'aarch64'] },
    ui: { source: { dockerTag: IMAGES.ui }, arch: ['x86_64', 'aarch64'] },
  },
  hardwareRequirements: {
    ram: 512 * 1024 ** 2, // 512 MiB: every service is a small static binary
  },
  dependencies: {
    'lightning-fork': {
      description: 'The Lightning node the wallet pays through. The wallet mounts only its tls.cert; you give it a narrow macaroon on the Lightning page.',
      optional: false,
      metadata: {
        title: 'Lightning Fork',
        icon: 'https://raw.githubusercontent.com/paulscode/lightning-fork-startos/master/icon.png',
      },
    },
  },
})
