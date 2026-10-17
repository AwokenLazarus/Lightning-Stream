import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'
import { IMAGES } from '../spec'

// The images are the local, multi-platform tags scripts/oci_build.sh --load makes (the image set the Umbrel apps
// and the wallet package use); `start-cli s9pk pack` takes each architecture from the local Docker. They are
// never pulled or pushed. StartOS runs x86_64 and aarch64 (the images also exist for arm/v7).

export const manifest = setupManifest({
  id: 'lightning-stream-gateway',
  title: 'Lightning Stream Gateway',
  license: 'MIT OR Apache-2.0',
  packageRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  upstreamRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  marketingUrl: 'https://github.com/AwokenLazarus/Lightning-Stream',
  donationUrl: null,
  description: { short, long },
  volumes: ['main'],
  images: {
    init: { source: { dockerTag: IMAGES.init }, arch: ['x86_64', 'aarch64'] },
    gateway: { source: { dockerTag: IMAGES.gateway }, arch: ['x86_64', 'aarch64'] },
    ui: { source: { dockerTag: IMAGES.ui }, arch: ['x86_64', 'aarch64'] },
  },
  hardwareRequirements: {
    ram: 256 * 1024 ** 2, // 256 MiB: two small static binaries
  },
  dependencies: {
    'lightning-fork': {
      description: 'The Lightning node the gateway takes tickets on. The gateway mounts only its tls.cert; you give it two narrow macaroons on the setup page.',
      optional: false,
      metadata: {
        title: 'Lightning Fork',
        icon: 'https://raw.githubusercontent.com/paulscode/lightning-fork-startos/master/icon.png',
      },
    },
  },
})
