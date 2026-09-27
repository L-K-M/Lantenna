<script>
  import 'osmium-ui/osmium.css';
</script>

<style>
  :global(html),
  :global(body) {
    margin: 0;
    padding: 0;
    width: 100%;
    height: 100%;
    overflow: hidden;
    background: transparent;
  }

  /* A push button dimmed while it keeps the keyboard ($lib/osm/actions
     dimmable), drawn as osmium.css draws :disabled, pressed or not. */
  :global(.osm-button[aria-disabled='true']),
  :global(.osm-button[aria-disabled='true'].osm-pressed) {
    border-image-source: var(--osm-sprite-button-disabled);
    color: #888;
  }
</style>

<slot />
