# Module contents

This module contains code generation logic that
takes matter IDL data as input and outputs rust tokens.

This module is explicitly *not* a proc-macro to allow
for unit testing, however it is intended to be very
thinly wrapper by proc macro modules.