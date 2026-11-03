# XR FastRPC integration

Independent upstream-derived FastRPC maintenance line shared by headset and controller components. The static host client exports XRHexagonRPC::client; xr-hexagonrpc-source supplies the same canonical source to ARM32/Bionic compatibility builds. Original copyright and GPL license notices are retained.

The shared component does not start another camera or DSP owner. Device-specific service ownership is managed by the selected session profile.
