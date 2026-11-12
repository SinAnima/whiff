"Berth allocation for Saltmere Harbour."
Object subclass: #Harbour
    instanceVariableNames: 'berths'
    classVariableNames: ''
    package: 'Saltmere-Harbour'!

!Harbour methodsFor: 'accessing'!
berths
    "Number of berths in the inner basin."
    ^ berths ifNil: [12]
! !
