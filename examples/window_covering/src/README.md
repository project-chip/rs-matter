# Status

Rough implementation of Window Covering device.

Currently only mandatory attributes exist. Device is commissionable to Homekit but gets displayed as unresponsive.

Not sure how best to define the Maps, hoping for feedback on that.
The Cluster implementation needs to vary depending on the features of the device.
I propose setting the attributes inside Option enums and implementing a general cluster checking for the current feature map.

Won't continue work on this until 22.08.2023, contributions are welcome to flesh this out.