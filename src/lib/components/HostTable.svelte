<script lang="ts">
    import type {Host} from '$lib/types';
    import { DataTable } from '@lkmc/system7-ui';
    import { getHostIcon } from '$lib/util/hostIcons';
    import { onMount, tick } from 'svelte';
    import { TauriService } from '$lib/tauri';
    import { formatRelativeTime, normalizeDisplayText, shortVendorName } from '$lib/util/format';
    import { notifications } from '$lib/util/notifications';
    import { primaryPortTarget } from '$lib/util/portTargets';

    export let hosts: Host[] = [];
    export let loading = false;
    export let selectedHostIp: string | null = null;
    export let customNames: Record<string, string> = {};
    export let favoriteIps: string[] = [];
    export let hiddenIps: string[] = [];
    export let staleFavoriteIps: string[] = [];
    export let newHostIps: string[] = [];
    export let onSelectHost: ((ip: string) => void) | undefined = undefined;
    export let onToggleFavorite: ((ip: string) => void) | undefined = undefined;
    export let onToggleHidden: ((ip: string) => void) | undefined = undefined;
    export let onClearCustomName: ((ip: string) => void) | undefined = undefined;
    export let emptyText = 'No hosts yet. Start a scan.';

    type SortField = 'ip' | 'favorite' | 'name' | 'fingerprint' | 'ports' | 'lastSeen';
    type SortDirection = 'asc' | 'desc';

    const columns = [
        { key: 'ip', label: 'IP', width: '190px', className: 'col-ip' },
        { key: 'name', label: 'Name', width: '24%', className: 'col-name' },
        { key: 'fingerprint', label: 'Fingerprint', width: '28%', className: 'col-fingerprint' },
        { key: 'ports', label: 'Open Ports', className: 'col-ports' },
        { key: 'lastSeen', label: 'Last Seen', width: '84px', className: 'col-seen' }
    ];

    interface ContextMenuState {
        open: boolean;
        x: number;
        y: number;
        ip: string;
    }

    // Drives the relative "Last Seen" labels.
    let now = Date.now();

    onMount(() => {
        const timer = setInterval(() => {
            now = Date.now();
        }, 60_000);
        return () => clearInterval(timer);
    });

    let sortField: SortField = 'favorite';
    let sortDirection: SortDirection = 'asc';

    const collator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});

    $: favoriteSet = new Set(favoriteIps);
    $: hiddenSet = new Set(hiddenIps);
    $: staleFavoriteSet = new Set(staleFavoriteIps);
    $: newHostSet = new Set(newHostIps);

    let contextMenu: ContextMenuState = {
        open: false,
        x: 0,
        y: 0,
        ip: ''
    };
    let contextMenuElement: HTMLDivElement | null = null;

    $: sortedHosts = [...hosts].sort((a, b) => {
        if (sortField === 'name') {
            const unnamed = Number(isUnnamed(a)) - Number(isUnnamed(b));
            if (unnamed !== 0) {
                return unnamed;
            }
        }

        const result = compareHosts(a, b, sortField, favoriteSet);
        if (result !== 0) {
            return sortDirection === 'asc' ? result : -result;
        }

        return ipToNumber(a.ip) - ipToNumber(b.ip);
    });

    function setSort(field: SortField) {
        if (sortField === field) {
            sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            return;
        }

        sortField = field;
        sortDirection = 'asc';
    }

    function ipToNumber(ip: string): number {
        const parts = ip.split('.').map((part) => Number(part));
        if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
            return Number.MAX_SAFE_INTEGER;
        }

        return parts[0] * 256 ** 3 + parts[1] * 256 ** 2 + parts[2] * 256 + parts[3];
    }

    function dateToNumber(iso: string): number {
        if (!iso) {
            return 0;
        }

        const timestamp = Date.parse(iso);
        if (Number.isNaN(timestamp)) {
            return 0;
        }
        return timestamp;
    }

    function compareHosts(a: Host, b: Host, field: SortField, favorites: Set<string>): number {
        switch (field) {
            case 'ip':
                return ipToNumber(a.ip) - ipToNumber(b.ip);
            case 'favorite':
                return Number(favorites.has(b.ip)) - Number(favorites.has(a.ip));
            case 'name':
                return collator.compare(displayName(a), displayName(b));
            case 'fingerprint':
                return collator.compare(formatFingerprint(a), formatFingerprint(b));
            case 'ports':
                return a.open_ports.length - b.open_ports.length;
            case 'lastSeen':
                return dateToNumber(a.last_seen) - dateToNumber(b.last_seen);
            default:
                return 0;
        }
    }

    const MAX_LISTED_PORTS = 6;

    /** Port numbers only, so more fit; the tooltip has the service names. */
    function formatPorts(host: Host): string {
        if (host.open_ports.length === 0) {
            return '-';
        }

        const numbers = host.open_ports.slice(0, MAX_LISTED_PORTS).map((port) => String(port.port));
        if (host.open_ports.length > MAX_LISTED_PORTS) {
            numbers.push(`+${host.open_ports.length - MAX_LISTED_PORTS}`);
        }

        return numbers.join(', ');
    }

    function describePorts(host: Host): string {
        return host.open_ports
            .map((port) => (port.service ? `${port.port} (${port.service})` : String(port.port)))
            .join(', ');
    }

    function formatTimestamp(iso: string): string {
        const date = new Date(iso);
        return Number.isNaN(date.getTime()) ? '' : date.toLocaleString();
    }

    function formatFingerprint(host: Host): string {
        const fp = host.fingerprint;
        if (!fp) {
            return 'Not fingerprinted yet';
        }

        const rawVendor = fp.vendor || fp.manufacturer;
        const vendor = rawVendor ? shortVendorName(normalizeDisplayText(rawVendor)) : 'Unknown vendor';
        const kind = normalizeDisplayText(fp.device_type || fp.os_guess || fp.model_guess || 'Unknown type');
        const confidence = Number.isFinite(fp.confidence) ? `${fp.confidence}%` : 'n/a';

        return `${vendor} • ${kind} (${confidence})`;
    }

    function toggleFavorite(event: MouseEvent, ip: string) {
        event.stopPropagation();
        onToggleFavorite?.(ip);
    }

    function favoriteLabel(ip: string): string {
        return favoriteSet.has(ip) ? `Unfavorite ${ip}` : `Favorite ${ip}`;
    }

    function hiddenLabel(ip: string): string {
        return hiddenSet.has(ip) ? `Unhide ${ip}` : `Hide ${ip}`;
    }

    function hasFriendlyName(ip: string): boolean {
        return (customNames[ip] || '').trim().length > 0;
    }

    function closeContextMenu() {
        if (!contextMenu.open) {
            return;
        }

        contextMenu = {
            open: false,
            x: 0,
            y: 0,
            ip: ''
        };
    }

    function selectHost(ip: string) {
        closeContextMenu();
        onSelectHost?.(ip);
    }

    async function openHost(host: Host) {
        const target = primaryPortTarget(host);
        if (!target) {
            notifications.add(`${host.ip} has no open web, file sharing, remote login or screen sharing port.`, 'info');
            return;
        }

        try {
            await TauriService.openExternalUrl(target.url);
        } catch (error) {
            const message =
                (typeof error === 'string' ? error : error instanceof Error ? error.message : '').trim() ||
                `Failed to open ${target.url}`;
            notifications.add(message, 'error');
        }
    }

    function openContextMenu(event: MouseEvent, ip: string) {
        event.preventDefault();
        event.stopPropagation();
        onSelectHost?.(ip);

        const menuWidth = 170;
        const menuHeight = 72;
        const maxX = Math.max(8, window.innerWidth - menuWidth - 8);
        const maxY = Math.max(8, window.innerHeight - menuHeight - 8);

        contextMenu = {
            open: true,
            x: Math.min(event.clientX, maxX),
            y: Math.min(event.clientY, maxY),
            ip
        };
    }

    function toggleHiddenFromContextMenu(ip: string) {
        onToggleHidden?.(ip);
        closeContextMenu();
    }

    function clearFriendlyNameFromContextMenu(ip: string) {
        if (!hasFriendlyName(ip)) {
            return;
        }

        onClearCustomName?.(ip);
        closeContextMenu();
    }

    function handleWindowPointerDown(event: MouseEvent) {
        if (!contextMenu.open) {
            return;
        }

        const target = event.target;
        if (contextMenuElement && target instanceof Node && contextMenuElement.contains(target)) {
            return;
        }

        closeContextMenu();
    }

    function handleWindowContextMenu(event: MouseEvent) {
        if (event.defaultPrevented) {
            return;
        }

        closeContextMenu();
    }

    function handleWindowKeydown(event: KeyboardEvent) {
        if (event.key === 'Escape') {
            closeContextMenu();
            return;
        }

        if (event.altKey || event.ctrlKey || event.metaKey || isTypingTarget(event.target) || sortedHosts.length === 0) {
            return;
        }

        if (event.key === 'Enter') {
            const selected = sortedHosts.find((host) => host.ip === selectedHostIp);
            if (selected) {
                event.preventDefault();
                void openHost(selected);
            }
            return;
        }

        if (event.key === 'ArrowDown') {
            event.preventDefault();
            moveSelection(1);
            return;
        }

        if (event.key === 'ArrowUp') {
            event.preventDefault();
            moveSelection(-1);
            return;
        }

        if (event.key === 'Home') {
            event.preventDefault();
            selectByIndex(0);
            return;
        }

        if (event.key === 'End') {
            event.preventDefault();
            selectByIndex(sortedHosts.length - 1);
            return;
        }

        if (event.key === 'PageDown') {
            event.preventDefault();
            moveSelection(10);
            return;
        }

        if (event.key === 'PageUp') {
            event.preventDefault();
            moveSelection(-10);
        }
    }

    function isTypingTarget(target: EventTarget | null): boolean {
        if (!(target instanceof HTMLElement)) {
            return false;
        }

        const tag = target.tagName.toLowerCase();
        if (tag === 'input' || tag === 'textarea' || tag === 'select' || tag === 'button') {
            return true;
        }

        return target.isContentEditable;
    }

    function selectByIndex(index: number) {
        if (sortedHosts.length === 0) {
            return;
        }

        const clampedIndex = Math.max(0, Math.min(index, sortedHosts.length - 1));
        const next = sortedHosts[clampedIndex];
        if (!next) {
            return;
        }

        closeContextMenu();
        onSelectHost?.(next.ip);
        void scrollSelectedRowIntoView();
    }

    async function scrollSelectedRowIntoView() {
        await tick();
        document.querySelector('.table-body-container tr.selected')?.scrollIntoView({ block: 'nearest' });
    }

    function moveSelection(offset: number) {
        if (sortedHosts.length === 0) {
            return;
        }

        const currentIndex = sortedHosts.findIndex((host) => host.ip === selectedHostIp);
        if (currentIndex < 0) {
            selectByIndex(offset >= 0 ? 0 : sortedHosts.length - 1);
            return;
        }

        selectByIndex(currentIndex + offset);
    }

    function isUnnamed(host: Host): boolean {
        return !(customNames[host.ip]?.trim() || host.name);
    }

    function displayName(host: Host): string {
        const customName = customNames[host.ip]?.trim() || '';
        return customName || host.name || 'Unknown';
    }

</script>

<svelte:window
        on:mousedown={handleWindowPointerDown}
        on:contextmenu={handleWindowContextMenu}
        on:keydown={handleWindowKeydown}
        on:resize={closeContextMenu}
        on:blur={closeContextMenu}
/>

<DataTable
        class="table-wrap"
        {columns}
        sortKey={sortField === 'favorite' ? null : sortField}
        sortDirection={sortDirection}
        loading={loading && hosts.length === 0}
        empty={!loading && hosts.length === 0}
        loadingText="Scanning..."
        {emptyText}
        emptyColspan={5}
        bodyClass="table-body-container"
>
    <svelte:fragment slot="header">
        <tr>
            <th class="col-ip">
                <div class="ip-header">
                    <button
                            type="button"
                            class="favorite-sort"
                            class:sorted={sortField === 'favorite'}
                            onclick={() => setSort('favorite')}
                            aria-label="Sort by favorites"
                            title="Sort by favorites"
                    >
                        <svg viewBox="0 0 16 16" role="img" focusable="false" aria-hidden="true">
                            <path d="M8 1.5l2 4 4.5.6-3.3 3.1.8 4.8L8 12l-4 2 0.8-4.8L1.5 6.1l4.5-.6L8 1.5z"/>
                        </svg>
                    </button>

                    <button
                            type="button"
                            class="sort-button"
                            class:sorted={sortField === 'ip'}
                            onclick={() => setSort('ip')}
                    >
                        IP
                    </button>
                </div>
            </th>
            <th class="col-name">
                <button
                        type="button"
                        class="sort-button"
                        class:sorted={sortField === 'name'}
                        onclick={() => setSort('name')}
                >
                    Name
                </button>
            </th>
            <th class="col-fingerprint">
                <button
                        type="button"
                        class="sort-button"
                        class:sorted={sortField === 'fingerprint'}
                        onclick={() => setSort('fingerprint')}
                >
                    Fingerprint
                </button>
            </th>
            <th class="col-ports">
                <button
                        type="button"
                        class="sort-button"
                        class:sorted={sortField === 'ports'}
                        onclick={() => setSort('ports')}
                >
                    Open Ports
                </button>
            </th>
            <th class="col-seen">
                <button
                        type="button"
                        class="sort-button"
                        class:sorted={sortField === 'lastSeen'}
                        onclick={() => setSort('lastSeen')}
                >
                    Last Seen
                </button>
            </th>
        </tr>
    </svelte:fragment>

    {#each sortedHosts as host}
        {@const hostIcon = getHostIcon(host, customNames[host.ip] || '')}

        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <tr
                class:selected={selectedHostIp === host.ip}
                class:hidden-entry={hiddenSet.has(host.ip)}
                class:stale={staleFavoriteSet.has(host.ip)}
                class:new-entry={newHostSet.has(host.ip)}
                onclick={() => selectHost(host.ip)}
                ondblclick={() => openHost(host)}
                oncontextmenu={(event) => openContextMenu(event, host.ip)}
        >
            <td class="col-ip">
                <div class="ip-cell">
                    <button
                            type="button"
                            class="favorite-toggle"
                            class:active={favoriteSet.has(host.ip)}
                            aria-label={favoriteLabel(host.ip)}
                            title={favoriteLabel(host.ip)}
                            onclick={(event) => toggleFavorite(event, host.ip)}
                    >
                        <svg viewBox="0 0 16 16" role="img" focusable="false" aria-hidden="true">
                            <path d="M8 1.5l2 4 4.5.6-3.3 3.1.8 4.8L8 12l-4 2 0.8-4.8L1.5 6.1l4.5-.6L8 1.5z"/>
                        </svg>
                    </button>
                    <img class="device-icon" src={hostIcon.src} alt="" aria-hidden="true" title={hostIcon.label}/>
                    <span class="ip-text">{host.ip}</span>
                    {#if newHostSet.has(host.ip)}
                        <span class="new-badge">NEW</span>
                    {/if}
                </div>
            </td>
            <td class="col-name">
                <span class="host-name">{displayName(host)}</span>
            </td>
            <td class="col-fingerprint">{formatFingerprint(host)}</td>
            <td class="col-ports" title={describePorts(host)}>{formatPorts(host)}</td>
            <td class="col-seen" title={formatTimestamp(host.last_seen)}>{formatRelativeTime(host.last_seen, now)}</td>
        </tr>
    {/each}
</DataTable>

{#if contextMenu.open}
    <div
            class="context-menu"
            bind:this={contextMenuElement}
            role="menu"
            style={`left: ${contextMenu.x}px; top: ${contextMenu.y}px;`}
    >
        <button
                type="button"
                class="context-menu-item"
                role="menuitem"
                onclick={() => toggleHiddenFromContextMenu(contextMenu.ip)}
        >
            {hiddenLabel(contextMenu.ip)}
        </button>
        <button
                type="button"
                class="context-menu-item"
                role="menuitem"
                disabled={!hasFriendlyName(contextMenu.ip)}
                onclick={() => clearFriendlyNameFromContextMenu(contextMenu.ip)}
        >
            Clear Friendly Name
        </button>
    </div>
{/if}

<style>
    .sort-button {
        border: none;
        background: transparent;
        color: inherit;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        letter-spacing: normal !important;
        font-feature-settings: normal !important;
        line-height: inherit;
        padding: 0;
        cursor: pointer;
        text-decoration: none;
        display: block;
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        text-align: left;
    }

    .sort-button.sorted {
        text-decoration: underline;
        text-underline-offset: 2px;
    }

    .ip-header {
        display: flex;
        align-items: center;
        gap: 6px;
        min-width: 0;
    }

    .ip-header .sort-button {
        flex: 1;
        min-width: 0;
        margin-left: 26px;
    }

    .favorite-sort,
    .favorite-toggle {
        border: 1px solid transparent;
        background: transparent;
        color: inherit;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
    }

    .favorite-sort {
        width: 14px;
        height: 14px;
    }

    .favorite-toggle {
        width: 16px;
        height: 16px;
        flex: 0 0 auto;
    }

    .favorite-sort svg,
    .favorite-toggle svg {
        width: 100%;
        height: 100%;
        fill: none;
        stroke: #000;
        stroke-width: 1.1;
        stroke-linejoin: round;
    }

    .favorite-sort.sorted svg,
    .favorite-sort:hover svg,
    .favorite-toggle.active svg,
    .favorite-toggle:hover svg {
        fill: var(--system7-color-accent, #000);
    }

    .col-ip {
        width: 190px;
    }

    .col-name {
        width: 24%;
    }

    .col-fingerprint {
        width: 28%;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .col-ports {
        width: auto;
    }

    .col-seen {
        width: 84px;
    }

    .ip-cell {
        display: flex;
        align-items: center;
        gap: 6px;
        min-width: 0;
    }

    .device-icon {
        width: 16px;
        height: 16px;
        image-rendering: pixelated;
        flex: 0 0 auto;
    }

    .ip-text,
    .host-name {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .ip-text {
        flex: 1 1 auto;
        min-width: 0;
    }

    .new-badge {
        font-size: 14px;
        line-height: 0.7;
        letter-spacing: 0.25px;
        border: 1px solid #6e6a54;
        padding: 2px 4px 2px 6px;
        background: #fff7bf;
        border-radius: 100px;
        color: #000;
        flex: 0 0 auto;
        display: inline-flex;
        align-items: center;
    }

    tr {
        cursor: pointer;
    }

    tr.stale td {
        color: #777;
    }

    tr.new-entry:not(.selected) td {
        background: #fff7bf;
    }

    tr.hidden-entry:not(.selected) td {
        color: #666;
        background: #f4f4f4;
    }

    tr.selected td {
        background: var(--system7-color-highlight, #000);
        color: var(--system7-color-highlight-text, #fff);
    }

    tr.selected .favorite-toggle svg {
        stroke: var(--system7-color-highlight-text, #fff);
    }

    tr.selected .new-badge {
        background: var(--system7-color-highlight-text, #fff);
        color: var(--system7-color-highlight, #000);
        border-color: var(--system7-color-highlight-text, #fff);
    }

    tr.selected .favorite-toggle.active svg {
        fill: var(--system7-color-highlight-text, #fff);
    }

    .context-menu {
        position: fixed;
        z-index: 3000;
        min-width: 210px;
        border: 1px solid #000;
        background: #fff;
        box-shadow: 2px 2px 0 #000;
        padding: 2px;
    }

    .context-menu-item {
        width: 100%;
        border: none;
        background: transparent;
        color: inherit;
        text-align: left;
        padding: 5px 8px;
        font-family: 'Sysfont', 'Chicago', 'Impact', sans-serif !important;
        font-size: 18px !important;
        font-weight: 400;
        letter-spacing: 1px;
        font-feature-settings: 'liga' off, 'clig' off, 'calt' off;
        cursor: pointer;
    }

    .context-menu-item:hover,
    .context-menu-item:focus-visible {
        background: var(--system7-color-accent, #000);
        color: var(--system7-color-accent-text, #fff);
        outline: none;
    }

    .context-menu-item:disabled {
        color: #808080;
        cursor: default;
    }

    .context-menu-item:disabled:hover,
    .context-menu-item:disabled:focus-visible {
        background: transparent;
        color: #808080;
        outline: none;
    }
</style>
