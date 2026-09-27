<!--
  Owner: unit C (spec 8.4). Spec: 2.7 (Fingerprint).
  SCAFFOLD STUB: an empty panel.
  Final: the Fingerprint panel of 2.7 for `row` (null: no selection).
-->
<svelte:options runes={true} />

<script lang="ts">
  import type { HostRow } from '$lib/app/hostModel';

  let { row }: { row: HostRow | null } = $props();
</script>

<div class="lan-info-fingerprint"></div>
