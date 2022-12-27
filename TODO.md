* udp.c:
  * Could get rid of 'smol' in here, no other processing is performed in this thread
* TLVList:
  * The 'Pointer' could be directly used in the TLVListIterator, makes it common
  * Not too happy with the way iterator_consumer is done for ContainerIterator, we could just zip the internal ListIterator instead?
  * Implement the IntoIterator Trait as well for the TLVElement. This was done earlier, but I backtracker after I ran into same lifetime issues
* Some configurable values like number of exchanges per session, number of sessions supported etc, can be bubbled up to some configurator for this crate. I wonder how that is done.
* About outgoing counter, is it incremented if we send mutliple acknowledgements to the same retransmitted packet? So let's say peer retransmits a packet with ctr 4, for 3 times. Our response ctr, is, say 20. Then should we respond with 20, 21, 22, or 20, 20, 20?
* I had to use Box::new() to pin ownership for certain objects. Not yet able to use try_new() in the stable releases, and I am not a fan of APIs that panic. We should mostly look at things like heapless:pool or stuff. These objects should really be in the bss, with a single ownership.
* It might be more efficient to avoid using .find_element() on TLVs. Earlier it was created this way because the spec mentions that the order may change, but it appears that this is unlikely, looking at the C++ implementation. If so, we could be faster, by just specifying looking for tag followed by value.
* PASE:
  - Pick some sensible and strong values for PBKDF2{iterCnt and Salt-length} based on SoC capability
  - Verifier should only store w0 and L, w1 shouldn't even be stored 
  - Allow some way to open the PASE window
  - Allow some way to pass in the 'passcode' and 'salt'
  - In case of error in any of the legs, return StatusReport
  - Provide a way to delete the exchange
  - SPAKE2+: the check with I (abort if `h*X == I`), as indicated by the RFC is pending

* Implement the ARM Fail Safe and Regulatory Config properly. Currently we just ack them to proceed further
* Currently AEAD, sha256 etc are directly used from rust crates. Instead use implementations from openssl/mbedtls - Done. Upstream MRs pending
* rust-mbedTLS: We have to do some gymnastics because current APIs only support signature encoded in ASN1 format. Fix this upstream
* CASE:
  - Handle initial MRP Parameters struct from Sigma1
* FailSafe:
  - Enable timer and expiration handling for fail-safe context
* Cert Verification:
  - Time validation (Not Before/Not After)
  - KeyUsage flags and others are pending
* Transport Mgr:
  - Add plain_encode and proto_encode in Packet
  - A new proto_tx should be created in the acks_to_send loop also, otherwise, there is a potential chance of reuse
  - 'transport' object's ownership needs to be inside session, or in the least 'exchange'
  - Sending 'close session' is pending on session reclamation because 'transport' object isn't owned
  - Convert the SessionHandle to &Session? Why maintain a separate object for this?
* Exchange:
  - What should happen when an exchange is closed by the higher layer, our tx-retrans is pending, and we got a retrans for that exchange?
* ACL:
  - Device-Type based ACLs
  - NOC CAT
  - Applying ACLs to commands (requires some restructuring of the commands)
  - I think we can the encoder to AccessReq Object making it a complete object for access within the DM
  - List processing of attribute write is missing in IM. List behaviour is add/edit/delete. Currently we only do 'add'
* Interaction Model
  - List processing of write attributes is different (delete, modify, edit), needs to be handled
* DataModel:
  - Shall we use a CmdEncoder as a parameter for all the handle_commands()?
  - Need to define common data types for cluster_id_t, endpoint_id_t so their sizes are constantly defined somewhere
 
