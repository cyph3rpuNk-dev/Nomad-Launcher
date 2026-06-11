//! Windows taskbar progress via `ITaskbarList3`.
//!
//! Maps [`crate::ui::ProgressState`] to `TBPF_*` flags so the launcher's
//! taskbar button shows determinate / indeterminate / error progress while the
//! pipeline runs. On non-Windows builds every method is a no-op.

/// Platform-specific window handle type: `*mut c_void` on Windows, `isize` elsewhere.
#[cfg(windows)]
pub type Hwnd = windows_sys::Win32::Foundation::HWND;
#[cfg(not(windows))]
pub type Hwnd = isize;

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    // ITaskbarList3 vtable — field order must exactly match the Win32 COM ABI:
    //   IUnknown (3) + ITaskbarList (5) + ITaskbarList2 (1) + ITaskbarList3 (first 2).
    #[repr(C)]
    struct Vtbl {
        query_interface:
            unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        hr_init: unsafe extern "system" fn(*mut c_void) -> i32,
        add_tab: unsafe extern "system" fn(*mut c_void, HWND) -> i32,
        delete_tab: unsafe extern "system" fn(*mut c_void, HWND) -> i32,
        activate_tab: unsafe extern "system" fn(*mut c_void, HWND) -> i32,
        set_active_alt: unsafe extern "system" fn(*mut c_void, HWND) -> i32,
        mark_fullscreen_window: unsafe extern "system" fn(*mut c_void, HWND, i32) -> i32,
        set_progress_value: unsafe extern "system" fn(*mut c_void, HWND, u64, u64) -> i32,
        set_progress_state: unsafe extern "system" fn(*mut c_void, HWND, u32) -> i32,
    }

    #[repr(C)]
    struct ComObj {
        vtbl: *const Vtbl,
    }

    // {56FDF344-FD6D-11D0-958A-006097C9A090}
    const CLSID_TASKBAR_LIST: GUID = GUID {
        data1: 0x56FD_F344,
        data2: 0xFD6D,
        data3: 0x11D0,
        data4: [0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90],
    };

    // {EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF}
    const IID_ITASKBAR_LIST3: GUID = GUID {
        data1: 0xEA1A_FB91,
        data2: 0x9E28,
        data3: 0x4B86,
        data4: [0x90, 0xE9, 0x9E, 0x9F, 0x8A, 0x5E, 0xEF, 0xAF],
    };

    const TBPF_NOPROGRESS: u32 = 0x0000;
    const TBPF_INDETERMINATE: u32 = 0x0001;
    const TBPF_NORMAL: u32 = 0x0002;
    const TBPF_ERROR: u32 = 0x0004;

    pub(super) struct Inner(*mut ComObj);

    // SAFETY: ITaskbarList3 is accessed only from the eframe main thread.
    unsafe impl Send for Inner {}

    impl Inner {
        pub(super) fn create() -> Option<Self> {
            let mut ptr: *mut c_void = std::ptr::null_mut();
            // SAFETY: COM is initialised by eframe/winit before the first update call.
            let hr = unsafe {
                CoCreateInstance(
                    &CLSID_TASKBAR_LIST,
                    std::ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_ITASKBAR_LIST3,
                    &mut ptr,
                )
            };
            if hr != 0 || ptr.is_null() {
                return None;
            }
            let obj = ptr.cast::<ComObj>();
            // SAFETY: ptr is a valid COM object returned by CoCreateInstance.
            let hr = unsafe { ((*(*obj).vtbl).hr_init)(obj.cast()) };
            if hr != 0 {
                // SAFETY: release the object before returning None.
                unsafe { ((*(*obj).vtbl).release)(obj.cast()) };
                return None;
            }
            Some(Self(obj))
        }

        fn vtbl(&self) -> &Vtbl {
            // SAFETY: self.0 is a valid COM object for the lifetime of Inner.
            unsafe { &*(*self.0).vtbl }
        }

        fn this(&self) -> *mut c_void {
            self.0.cast()
        }

        pub(super) fn set_indeterminate(&self, hwnd: HWND) {
            // SAFETY: hwnd is a valid window handle obtained from acquire_hwnd().
            unsafe { (self.vtbl().set_progress_state)(self.this(), hwnd, TBPF_INDETERMINATE) };
        }

        pub(super) fn set_progress(&self, hwnd: HWND, fraction: f32) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let completed = u64::from((fraction.clamp(0.0, 1.0) * 1000.0) as u32);
            // SAFETY: hwnd is a valid window handle obtained from acquire_hwnd().
            unsafe {
                (self.vtbl().set_progress_state)(self.this(), hwnd, TBPF_NORMAL);
                (self.vtbl().set_progress_value)(self.this(), hwnd, completed, 1000);
            }
        }

        pub(super) fn set_error(&self, hwnd: HWND) {
            // SAFETY: hwnd is a valid window handle obtained from acquire_hwnd().
            unsafe { (self.vtbl().set_progress_state)(self.this(), hwnd, TBPF_ERROR) };
        }

        pub(super) fn clear(&self, hwnd: HWND) {
            // SAFETY: hwnd is a valid window handle obtained from acquire_hwnd().
            unsafe { (self.vtbl().set_progress_state)(self.this(), hwnd, TBPF_NOPROGRESS) };
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: self.0 is a valid COM object pointer.
                unsafe { ((*(*self.0).vtbl).release)(self.0.cast()) };
            }
        }
    }
}

/// Locates the first visible window belonging to the current process.
///
/// Returns the window handle on Windows, or `None` when no visible process
/// window is found or on non-Windows builds.
#[must_use]
pub fn acquire_hwnd() -> Option<Hwnd> {
    #[cfg(windows)]
    {
        use std::ffi::c_void;

        use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
        };

        struct State {
            pid: u32,
            hwnd: HWND,
        }

        unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            // SAFETY: lparam is a valid *mut State cast to LPARAM.
            let state = unsafe { &mut *(lparam as *mut State) };
            let mut pid: u32 = 0;
            // SAFETY: hwnd is a valid HWND supplied by EnumWindows.
            unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
            // SAFETY: hwnd is a valid HWND supplied by EnumWindows.
            if pid == state.pid && unsafe { IsWindowVisible(hwnd) } != 0 {
                state.hwnd = hwnd;
                return 0; // stop enumeration
            }
            1 // continue
        }

        let mut state = State {
            // SAFETY: no preconditions for GetCurrentProcessId.
            pid: unsafe { GetCurrentProcessId() },
            hwnd: std::ptr::null_mut::<c_void>(),
        };
        // SAFETY: callback is a valid WNDENUMPROC; lparam is a live *mut State.
        unsafe { EnumWindows(Some(callback), std::ptr::addr_of_mut!(state) as LPARAM) };
        if state.hwnd.is_null() {
            None
        } else {
            Some(state.hwnd)
        }
    }
    #[cfg(not(windows))]
    None
}

// ── Public facade ─────────────────────────────────────────────────────────────

/// Drives `ITaskbarList3` taskbar-button progress for the launcher window.
///
/// Created once during window setup; each frame's [`crate::ui::ProgressState`]
/// and phase are mapped to the appropriate `TBPF_*` flag. On non-Windows
/// builds or when COM initialisation fails all methods are silent no-ops.
pub struct TaskbarProgress {
    #[cfg(windows)]
    inner: Option<imp::Inner>,
}

impl TaskbarProgress {
    /// Creates an `ITaskbarList3` COM object. Silently degrades on failure.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            inner: imp::Inner::create(),
        }
    }

    /// Applies taskbar state for the current frame.
    ///
    /// `is_error` takes priority: when true the button turns red regardless
    /// of `progress`. `hwnd` must be the launcher window handle.
    pub fn apply(&self, hwnd: Hwnd, progress: &crate::ui::ProgressState, is_error: bool) {
        #[cfg(windows)]
        {
            let Some(ref inner) = self.inner else {
                return;
            };
            if is_error {
                inner.set_error(hwnd);
            } else {
                match progress {
                    crate::ui::ProgressState::Indeterminate => inner.set_indeterminate(hwnd),
                    crate::ui::ProgressState::Determinate(f) => inner.set_progress(hwnd, *f),
                    crate::ui::ProgressState::Hidden => inner.clear(hwnd),
                }
            }
        }
        #[cfg(not(windows))]
        let _ = (hwnd, progress, is_error);
    }
}

impl Default for TaskbarProgress {
    fn default() -> Self {
        Self::new()
    }
}
