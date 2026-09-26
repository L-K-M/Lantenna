/**
 * Locally administered MACs (bit 0x02 of the first octet) are the randomized
 * "private" addresses of phones and tablets, or belong to VMs and containers.
 * They have no registered vendor. Malformed input is not private.
 */
export function isPrivateMac(mac: string | null | undefined): boolean {
  const firstOctet = /^[0-9a-f]{2}(?=[:-])/i.exec((mac || '').trim());
  if (!firstOctet) {
    return false;
  }

  return (Number.parseInt(firstOctet[0], 16) & 0x02) !== 0;
}
