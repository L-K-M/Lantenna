/**
 * Locally administered MACs (bit 0x02 of the first octet) are the randomized
 * "private" addresses of phones and tablets, or belong to VMs and containers.
 * They have no registered vendor.
 */
export function isPrivateMac(mac: string | null | undefined): boolean {
  if (!mac) {
    return false;
  }

  const firstOctet = Number.parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(firstOctet) && (firstOctet & 0x02) !== 0;
}
