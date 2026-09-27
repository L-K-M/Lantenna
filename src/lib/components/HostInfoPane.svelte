<!--
  Owner: unit C (spec 8.4). Spec: 2.3 (pane rows), 2.7, 5.3.
  SCAFFOLD STUB: the empty 300px pane holding the three stub panels.
  Final: General / Ports / Fingerprint tabs (mountTabs, panels always
  mounted, front tab in ui.infoTab), the host status line, Wake,
  Deep Scan and the default Open button with bindDialogKeys; an
  InfoPaneApi published in infoPaneApi (views.ts).
  It hides itself with the `hidden` attribute when the pane is hidden, so
  drafts and scroll positions survive. The page's CSS owns the region
  box (.lan-pane, 300px, position: relative).
  The panels' root elements (InfoGeneral, InfoPorts, InfoFingerprint)
  become Osmium-owned once mountTabs runs: it sets their hidden, id,
  role and aria-labelledby. Give them a static class plus class: and
  style: directives only, never hidden={...}, id={...} or class={...}.
-->
<svelte:options runes={true} />

<script lang="ts">
  import { hostModel } from '$lib/app/hostModel';
  import { ui } from '$lib/app/ui';
  import InfoFingerprint from './InfoFingerprint.svelte';
  import InfoGeneral from './InfoGeneral.svelte';
  import InfoPorts from './InfoPorts.svelte';
</script>

<div class="lan-pane" hidden={!$ui.infoPaneShown}>
  <InfoGeneral row={$hostModel.selected} />
  <InfoPorts row={$hostModel.selected} />
  <InfoFingerprint row={$hostModel.selected} />
</div>
