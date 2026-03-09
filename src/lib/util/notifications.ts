import { writable } from 'svelte/store';

export type NotificationType = 'success' | 'error' | 'info';

export interface NotificationItem {
  id: number;
  message: string;
  type: NotificationType;
}

function createNotificationStore() {
  const { subscribe, update } = writable<NotificationItem[]>([]);
  let counter = 0;

  return {
    subscribe,
    add: (message: string, type: NotificationType = 'info') => {
      const id = counter++;
      update((items) => [...items, { id, message, type }]);

      setTimeout(() => {
        update((items) => items.filter((item) => item.id !== id));
      }, 5000);
    }
  };
}

export const notifications = createNotificationStore();
