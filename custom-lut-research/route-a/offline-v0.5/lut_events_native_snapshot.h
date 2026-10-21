/* Native callers cache the 96-byte G+0x68 descriptor in their 120-byte
 * configuration context. Copy their context once, then hold and validate the
 * complete descriptor (including its generation) before any native use.
 * Do not silently replace a stale caller's intended configuration with G.
 */
INLINE void native_snapshot(u32 owner,const u32 *context) {
    typedef void (*apply)(u32,const u32 *);
    if(!owner) return;
    u32 copy[30];
    for(u32 i=0;i<30;i++) copy[i]=context[i];
    if(!copy[0]) return;
    if(copy[2]!=10) {((apply)LUT_NATIVE_APPLY_ORIGINAL)(owner,copy);return;}
    u32 token=((u32 (*)(struct lh_cp *))CP_READER_BEGIN)(CP);
    if(!token) return;
    const volatile u32 *live=(const volatile u32 *)0x165a788U;
    u32 same=1;
    for(u32 i=0;i<24;i++) if(copy[6+i]!=live[i]) {same=0;break;}
    if(same) ((apply)LUT_NATIVE_APPLY_ORIGINAL)(owner,copy);
    if(!reader_end(token,0)) quarantine();
}
