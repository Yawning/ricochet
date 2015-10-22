### ricochet (Go lang ricochet-im library).
#### Yawning Angel (yawning at schwanenlied dot me)

Go language [ricochet](https://github.com/ricochet-im) protocol implementation.
This should be a complete implementation of the version 1 protocol, with
behavior that mostly matches the reference implementation.

Dependencies:
 * https://golang.org/x/net/proxy
 * https://github.com/eapache/channels
 * https://github.com/golang/protobuf
 * https://github.com/yawning/bulb
 * Tor 0.2.7.x

Notes:
  * For convenience, the auto-generated protobuf compiler output is checked
    into the repository so that the protobuf compiler is not needed.
  * It assumes that you have a recent enough Tor that `ADD_ONION` is
    available, and uses it to create the Hidden Service.
  * Only tested on Linux, with Go 1.5.1.  It should work on other systems.
  * It's CC0 for a reason, do what you want, I don't care.  Bug reports and
    reasonable patches accepted.  Otherwise leave me alone.

