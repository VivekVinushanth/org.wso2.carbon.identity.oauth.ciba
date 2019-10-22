## Reason for Implementation
* In all of the flows initiated by the RP[Relying Party-client App] in regard to  OpenID Connect Authentication flow, the end-user interaction from the consumption device is required and are based on HTTP redirection mechanisms. 

* But there has become a necessity where the RP needs to be the initiator of the user authentication flow and end-user interaction from the consumption device is not needed.

* That is, required to decouple consumption device[RP] from Authentication.CIBA decouples the Consumption device [Say POS] from Authentication device [eg: Phone]. 

## Flow as per the spec:

![flow](https://miro.medium.com/max/1000/1*hIH7HdHg6P9eaRby1zA1Gg.png)
* This specification does not change the semantics of the OpenID Connect Authentication flow. 
* It introduces a new endpoint to which the authentication request is posted. 
* It introduces a new asynchronous method for authentication result notification or delivery. 
* It does not introduce new scope values nor does it change the semantics of standard OpenID Connect parameters.

1. Consumption device obtains a valid identifier for the user they want to authenticate.
2. Consumption device initiates an interaction flow to authenticate their users(Authentication Request).
3. Authorization Issues a Authentication Response.
4. Authorization Server, requests Authentication Device for Consent and credentials. 
5. Authentication Device prompts for credentials and consent.
6. End User provides consent and Credentials.
7. Authorization Server authenticates and send Notification to Consumption device about Token.
8. Consumption device requests Token.
9. Authorization sends Token Response.

* The flow after 6 varies according to modes - Poll,Ping,Push.
* But Push is neglected for Financial grade API because of compromised security features.
* So, we will not be implementing Push mode.

##Custom Flow
![Sequence of the Flow] (https://miro.medium.com/max/1576/1*5VJP-zVlIBHV739doqT4vA.png)
*This is the sequence flow of events that WSO2 - IS is going to handle in regard to CIBA.

## Design

We planned to deploy CIBA feature with aid of two components
1. CibaEndPoint
2. CibaComponent

![High Level Architecture](https://miro.medium.com/max/2753/1*k1qforLqv0t55dgNT1i-Bg.png)
*This repository is for the CibaComponent.


### Further Readup:
* Spec: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
* External Blog : https://blog.usejournal.com/lets-break-up-dear-decouple-ourselves-88159a86aba
* External Blog : https://medium.com/@vivekc.16/people-you-dont-expect-to-operate-from-area-51-93646a58f485
