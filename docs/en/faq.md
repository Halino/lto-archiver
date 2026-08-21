# FAQ

**Why can LTFS close be long?** `CopyFileEx` may await provider work; StoreOpen
may still flush cache/metadata. Wait for `close.complete`.

**Does Explorer close differently?** The app uses Windows `CopyFileEx`, the
same system copy path, but Explorer is not a mounted-tape operator tool.

**Can handles be deferred?** No. The app owns/closes its handle and cannot
transfer it to StoreOpen; one file runs at a time with no final handle queue.

**Why no unmount timeout?** StoreOpen owns LTFS index sync, letter release and
ejection. Forced timeout cannot safely complete them; wait for `unmount.progress`.

**What do graph lines/axes mean?** Effective tape average includes elapsed
time. LTFS cache admission is separate and can exceed tape speed. Five minutes
uses one-second samples, gaps for missing cache data, separate left/right 0/50/100% scales.

**When clean head?** Only flashing Clean LED or TapeAlert/support `Clean Now`,
`Clean Periodic`, `Clean requested`; use `C7978A`, never swabs/preventative clean.

**Disable Defender?** No: use only narrow CFA executable allow-list.

**Are jobs FIFO?** No. Saved needs explicit start; `run.lock` is no scheduler.

**Can a file span tapes?** No; plan keeps it on one tape block.

**Is HPE software included?** No: StoreOpen, drivers, firmware, L&TT/installers
are external prerequisites and are not redistributed.
