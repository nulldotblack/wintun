use std::{
    ffi, future::Future, pin::Pin, sync::{
        atomic::{AtomicBool, AtomicPtr, Ordering},
        Arc,
    }, task::{Context, Poll, Waker}
};
use crate::{util, Error, Packet, Result, Session};
use atomic_waker::AtomicWaker;

use windows_sys::Win32::{
    Foundation::{
        HANDLE,
    },
    System::Threading::{RegisterWaitForSingleObject, UnregisterWaitEx, INFINITE},
};

use futures::{future::Either, io::{AsyncRead, AsyncWrite}};

pub struct AsyncSession {
    session: Arc<Session>,
    read_waiter: Pin<Box<WaitForHandle>>,
    shutdown_waiter: Pin<Box<WaitForHandle>>,
}

impl AsyncSession {
    pub (crate) fn new(session: Arc<Session>) -> Result<Self> {
        let read_waiter = Box::pin(WaitForHandle::new(session.get_read_wait_event()?)?);
        let shutdown_waiter = Box::pin(WaitForHandle::new(session.shutdown_event)?);
        Ok(Self {
            session,
            read_waiter,
            shutdown_waiter,
        })
    }

    // TODO: do something about exclusive reference - maybe split into SendHandle that the user can expect to clone / own?
    pub async fn receive(&mut self) -> Result<Packet, Error> {
        loop {
            match self.session.try_receive() {
                Ok(Some(packet)) => return Ok(packet),
                Ok(None) => {
                    let result = futures::future::select(self.read_waiter.as_mut(), self.shutdown_waiter.as_mut()).await;
                    match result {
                        Either::Left((_, _)) => {
                            // Read handle signaled, try to receive again
                            continue;
                        }
                        Either::Right((_, _)) => {
                            // Shutdown handle signaled
                            return Err(Error::ShuttingDown);
                        }
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }
}

struct WaitForHandle {
    inner: Arc<WaitForHandleInner>
}

struct WaitForHandleInner {
    handle: HANDLE,
    callback_handle: AtomicPtr<ffi::c_void>,
    waker: AtomicWaker,
    done: AtomicBool,
}

impl WaitForHandle {
    pub fn new(handle: HANDLE) -> Result<Self> {

        let mut inner = Arc::new(WaitForHandleInner {
            handle,
            callback_handle: AtomicPtr::new(std::ptr::null_mut()),
            waker: AtomicWaker::new(),
            done: AtomicBool::new(false)
        });

        let mut wait_handle: HANDLE = std::ptr::null_mut();
        let result = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_handle,
                handle,
                Some(wait_callback),
                Arc::into_raw(Arc::clone(&inner)) as *const WaitForHandleInner as *const _,
                INFINITE,
                0,
            )
        };
        if result == 0 {
            return Err(util::get_last_error().into());
        }
        inner.callback_handle.store(wait_handle, Ordering::Release);

        Ok(WaitForHandle {
            inner
        })
    }
}

impl Future for WaitForHandle {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.inner.done.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        } else {
            println!("Registering waker");
            self.inner.waker.register(cx.waker()); 

            Poll::Pending
        }
    }
}

impl Drop for WaitForHandle {
    fn drop(&mut self) {
        let _ = self.inner.waker.take();
        // Unregister the wait handle
        let callback_handle = self.inner.callback_handle.load(Ordering::Acquire);
        unsafe {
            // Use UnregisterWaitEx with INVALID_HANDLE_VALUE to wait until all callbacks have completed
            UnregisterWaitEx(callback_handle, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
        }
    }
}

extern "system" fn wait_callback(context: *mut std::ffi::c_void, _: u8) {
    let inner = unsafe { Arc::from_raw(context as *mut WaitForHandleInner) };
    inner.done.store(true, Ordering::SeqCst);

    inner.waker.wake();
    // Do not drop the Arc, it will be dropped when the Future is dropped
    // TODO: is this true? we need to wait for UnregisterWaitEx to wait until all callbacks get called,
    // and we have a guarntee that this function will never be called again
    std::mem::forget(inner);
}