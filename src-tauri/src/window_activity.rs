use tauri::{Emitter, WebviewWindow};

#[cfg(target_os = "linux")]
use gtk::{gdk::WindowState, glib::Propagation, prelude::*};

const ACTIVITY_CHANGED: &str = "window-activity-changed";

#[cfg(target_os = "linux")]
pub(crate) fn track(window: &WebviewWindow) -> tauri::Result<()> {
    let native = window.gtk_window()?;
    let window = window.clone();

    // Match GTK's own decorations. Move grabs can drop keyboard focus while
    // GDK_WINDOW_STATE_FOCUSED (active decorations) remains set.
    native.connect_window_state_event(move |_, event| {
        if event.changed_mask().contains(WindowState::FOCUSED) {
            let active = event.new_window_state().contains(WindowState::FOCUSED);
            let _ = window.emit(ACTIVITY_CHANGED, active);
        }
        Propagation::Proceed
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn track(window: &WebviewWindow) -> tauri::Result<()> {
    let emitter = window.clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::Focused(active) = event {
            let _ = emitter.emit(ACTIVITY_CHANGED, *active);
        }
    });
    Ok(())
}

// Synchronous Tauri commands run on the main thread, as GTK requires.
#[tauri::command]
pub(crate) fn is_window_active(window: WebviewWindow) -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        let native = window.gtk_window().map_err(|error| error.to_string())?;
        Ok(native
            .window()
            .is_some_and(|window| window.state().contains(WindowState::FOCUSED)))
    }
    #[cfg(not(target_os = "linux"))]
    window.is_focused().map_err(|error| error.to_string())
}
