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

  /* The check mark of a checked menu item or chosen pop-up item is
     osmium.css generated content, which would count toward the item's
     accessible name ("✓ as List") next to its aria-checked or
     aria-selected; empty alternative text leaves it out. The plain
     declaration is for WebKit without alternative text (before Safari
     17.4). Osmium follow-up. */
  :global(html .osm-menu-item[aria-selected='true']::before),
  :global(html .osm-menu-item[aria-checked='true']::before) {
    content: '\2713';
    content: '\2713' / '';
  }
</style>

<slot />
