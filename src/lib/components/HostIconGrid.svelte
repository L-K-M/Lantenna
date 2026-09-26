<script lang="ts">
    import type {Host} from '$lib/types';
    import {tick} from 'svelte';
    import {TauriService} from '$lib/tauri';
    import {getHostIcon} from '$lib/util/hostIcons';
    import {notifications} from '$lib/util/notifications';
    import {primaryPortTarget} from '$lib/util/portTargets';

    export let hosts: Host[] = [];
    export let loading = false;
    export let selectedHostIp: string | null = null;
    export let customNames: Record<string, string> = {};
    export let favoriteIps: string[] = [];
    export let hiddenIps: string[] = [];
    export let staleFavoriteIps: string[] = [];
    export let newHostIps: string[] = [];
    export let emptyText = 'No hosts yet. Start a scan.';
    export let onSelectHost: ((ip: string) => void) | undefined = undefined;

    let gridElement: HTMLDivElement | null = null;

    $: favoriteSet = new Set(favoriteIps);
    $: hiddenSet = new Set(hiddenIps);
    $: staleSet = new Set(staleFavoriteIps);
    $: newHostSet = new Set(newHostIps);

    // Favorites first, like the list's default sort, then by address.
    $: orderedHosts = [...hosts].sort(
        (a, b) => Number(favoriteSet.has(b.ip)) - Number(favoriteSet.has(a.ip)) || ipToNumber(a.ip) - ipToNumber(b.ip)
    );

    function ipToNumber(ip: string): number {
        const parts = ip.split('.').map((part) => Number(part));
        if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
            return Number.MAX_SAFE_INTEGER;
        }

        return parts[0] * 256 ** 3 + parts[1] * 256 ** 2 + parts[2] * 256 + parts[3];
    }

    function displayName(host: Host): string {
        return customNames[host.ip]?.trim() || host.name?.replace(/\.local$/, '') || host.ip;
    }

    async function openHost(host: Host) {
        const target = primaryPortTarget(host);
        if (!target) {
            notifications.add(`${host.ip} has no open web, file sharing or remote login port.`, 'info');
            return;
        }

        try {
            await TauriService.openExternalUrl(target.url);
        } catch (error) {
            const message = typeof error === 'string' ? error : `Failed to open ${target.url}`;
            notifications.add(message, 'error');
        }
    }

    /** Tiles in the first row, i.e. how far Up/Down moves. */
    function columnCount(): number {
        const tiles = gridElement?.querySelectorAll<HTMLElement>('.tile');
        if (!tiles || tiles.length === 0) {
            return 1;
        }

        const firstRowTop = tiles[0].offsetTop;
        let columns = 0;
        for (const tile of tiles) {
            if (tile.offsetTop !== firstRowTop) {
                break;
            }
            columns += 1;
        }

        return Math.max(1, columns);
    }

    async function selectIndex(index: number) {
        if (orderedHosts.length === 0) {
            return;
        }

        const clamped = Math.max(0, Math.min(index, orderedHosts.length - 1));
        onSelectHost?.(orderedHosts[clamped].ip);
        await tick();

        // Focus follows the selection, as in a list box, so the focus ring
        // never marks a different tile than the highlight.
        const selectedTile = gridElement?.querySelector<HTMLElement>('.tile.selected');
        selectedTile?.focus({preventScroll: true});
        selectedTile?.scrollIntoView({block: 'nearest'});
    }

    function isTypingTarget(target: EventTarget | null): boolean {
        if (!(target instanceof HTMLElement)) {
            return false;
        }

        // Tiles are buttons, but arrow keys on them should move the selection.
        if (target.closest('.icon-grid')) {
            return false;
        }

        const tag = target.tagName.toLowerCase();
        return tag === 'input' || tag === 'textarea' || tag === 'select' || tag === 'button' || target.isContentEditable;
    }

    function handleWindowKeydown(event: KeyboardEvent) {
        if (event.altKey || event.ctrlKey || event.metaKey || isTypingTarget(event.target) || orderedHosts.length === 0) {
            return;
        }

        const current = orderedHosts.findIndex((host) => host.ip === selectedHostIp);
        const columns = columnCount();
        const moves: Record<string, number> = {
            ArrowRight: 1,
            ArrowLeft: -1,
            ArrowDown: columns,
            ArrowUp: -columns
        };

        if (event.key in moves) {
            event.preventDefault();
            const step = moves[event.key];
            void selectIndex(current < 0 ? (step > 0 ? 0 : orderedHosts.length - 1) : current + step);
            return;
        }

        if (event.key === 'Home' || event.key === 'End') {
            event.preventDefault();
            void selectIndex(event.key === 'Home' ? 0 : orderedHosts.length - 1);
            return;
        }

        if (event.key === 'Enter' && current >= 0) {
            event.preventDefault();
            void openHost(orderedHosts[current]);
        }
    }
</script>

<svelte:window on:keydown={handleWindowKeydown}/>

<div class="icon-grid" role="listbox" aria-label="Hosts" bind:this={gridElement}>
    {#if loading && hosts.length === 0}
        <p class="placeholder">Scanning...</p>
    {:else if hosts.length === 0}
        <p class="placeholder">{emptyText}</p>
    {:else}
        {#each orderedHosts as host (host.ip)}
            {@const icon = getHostIcon(host, customNames[host.ip] || '')}
            <button
                    type="button"
                    class="tile"
                    class:selected={selectedHostIp === host.ip}
                    class:dimmed={staleSet.has(host.ip) || hiddenSet.has(host.ip)}
                    role="option"
                    aria-selected={selectedHostIp === host.ip}
                    title={`${displayName(host)} (${host.ip}): ${icon.label}`}
                    onclick={() => onSelectHost?.(host.ip)}
                    ondblclick={() => openHost(host)}
            >
                <span class="tile-icon">
                    <img src={icon.src} alt="" width="32" height="32"/>
                    {#if favoriteSet.has(host.ip)}
                        <span class="tile-star" aria-label="Favorite">★</span>
                    {/if}
                </span>
                <span class="tile-name">{displayName(host)}</span>
                <span class="tile-meta">
                    {host.ip}
                    {#if newHostSet.has(host.ip)}<span class="tile-new">NEW</span>{/if}
                </span>
            </button>
        {/each}
    {/if}
</div>

<style>
    .icon-grid {
        flex: 1;
        min-width: 0;
        min-height: 0;
        overflow-y: auto;
        padding: 14px 12px;
        display: grid;
        grid-template-columns: repeat(auto-fill, 112px);
        grid-auto-rows: max-content;
        gap: 14px 6px;
        align-content: start;
        background: var(--system7-color-paper, #fff);
    }

    .placeholder {
        grid-column: 1 / -1;
        text-align: center;
        color: var(--system7-color-disabled-ink, #808080);
        font-style: italic;
        margin: 8px 0;
    }

    .tile {
        border: none;
        background: transparent;
        color: inherit;
        padding: 2px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        cursor: pointer;
        font: inherit;
    }

    .tile:focus-visible {
        outline: 1px dotted var(--system7-color-ink, #000);
        outline-offset: 1px;
    }

    .tile-icon {
        position: relative;
        width: 32px;
        height: 32px;
    }

    .tile-icon img {
        width: 32px;
        height: 32px;
        image-rendering: pixelated;
    }

    /* System 7 marks a selected icon by darkening it and inverting its label. */
    .tile.selected .tile-icon img {
        filter: brightness(0.45);
    }

    .tile-star {
        position: absolute;
        top: -6px;
        right: -10px;
        font-size: 12px;
        line-height: 1;
    }

    .tile-name {
        max-width: 108px;
        padding: 0 3px;
        font-size: 0.9em;
        line-height: 1.15;
        text-align: center;
        overflow-wrap: break-word;
        display: -webkit-box;
        -webkit-line-clamp: 2;
        line-clamp: 2;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }

    .tile.selected .tile-name {
        background: var(--system7-color-highlight, #000);
        color: var(--system7-color-highlight-text, #fff);
    }

    .tile-meta {
        font-size: 0.85em;
        color: #666;
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }

    .tile-new {
        border: 1px solid var(--system7-color-ink, #000);
        padding: 0 2px;
        line-height: 1;
        font-size: 0.8em;
        color: var(--system7-color-ink, #000);
    }

    .tile.dimmed {
        opacity: 0.5;
    }
</style>
