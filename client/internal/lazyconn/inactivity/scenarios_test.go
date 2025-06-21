package inactivity

import "time"

type scenario struct {
	ExpectedInactive bool
	Data             []rxHistory
}

var scenarios = []scenario{
	{
		ExpectedInactive: true,
		Data: []rxHistory{
			{when: 0 * time.Second, RxBytes: 32},
			{when: 25 * time.Second, RxBytes: 32},
			{when: 50 * time.Second, RxBytes: 32},
			{when: 75 * time.Second, RxBytes: 32},
			{when: 100 * time.Second, RxBytes: 32},
			{when: 100 * time.Second, RxBytes: 92},
			{when: 150 * time.Second, RxBytes: 32},
			{when: 175 * time.Second, RxBytes: 32},
			{when: 200 * time.Second, RxBytes: 32},
			{when: 225 * time.Second, RxBytes: 32},
			{when: 250 * time.Second, RxBytes: 32},
			{when: 250 * time.Second, RxBytes: 92},
			{when: 300 * time.Second, RxBytes: 32},
			{when: 325 * time.Second, RxBytes: 32},
			{when: 350 * time.Second, RxBytes: 32},
			{when: 375 * time.Second, RxBytes: 32},
			{when: 375 * time.Second, RxBytes: 92},
			{when: 400 * time.Second, RxBytes: 32},
			{when: 425 * time.Second, RxBytes: 32},
			{when: 450 * time.Second, RxBytes: 32},
			{when: 475 * time.Second, RxBytes: 32},
			{when: 500 * time.Second, RxBytes: 32},
			{when: 500 * time.Second, RxBytes: 92},
			{when: 525 * time.Second, RxBytes: 32},
			{when: 550 * time.Second, RxBytes: 32},
			{when: 575 * time.Second, RxBytes: 32},
			{when: 600 * time.Second, RxBytes: 32},
			{when: 625 * time.Second, RxBytes: 32},
			{when: 625 * time.Second, RxBytes: 92},
			{when: 650 * time.Second, RxBytes: 32},
			{when: 675 * time.Second, RxBytes: 32},
			{when: 700 * time.Second, RxBytes: 32},
			{when: 725 * time.Second, RxBytes: 32},
			{when: 750 * time.Second, RxBytes: 32},
			{when: 750 * time.Second, RxBytes: 92},
			{when: 775 * time.Second, RxBytes: 32},
		},
	},
	{
		ExpectedInactive: true,
		Data: []rxHistory{
			//96
			{when: 0 * time.Second, RxBytes: 32},
			{when: 25 * time.Second, RxBytes: 32},
			{when: 50 * time.Second, RxBytes: 32},

			//212
			{when: 75 * time.Second, RxBytes: 32},
			{when: 100 * time.Second, RxBytes: 32},
			{when: 100 * time.Second, RxBytes: 148},

			//96
			{when: 125 * time.Second, RxBytes: 32},
			{when: 150 * time.Second, RxBytes: 32},
			{when: 175 * time.Second, RxBytes: 32},

			//212
			{when: 200 * time.Second, RxBytes: 32},
			{when: 225 * time.Second, RxBytes: 32},
			{when: 225 * time.Second, RxBytes: 148},

			//96
			{when: 250 * time.Second, RxBytes: 32},
			{when: 275 * time.Second, RxBytes: 32},
			{when: 300 * time.Second, RxBytes: 32},

			{when: 325 * time.Second, RxBytes: 32},
			{when: 350 * time.Second, RxBytes: 32},
			{when: 350 * time.Second, RxBytes: 148},

			{when: 375 * time.Second, RxBytes: 32},
			{when: 400 * time.Second, RxBytes: 32},

			{when: 425 * time.Second, RxBytes: 32},
			{when: 450 * time.Second, RxBytes: 32},
			{when: 475 * time.Second, RxBytes: 32},
			{when: 475 * time.Second, RxBytes: 148},

			{when: 500 * time.Second, RxBytes: 32},
			{when: 525 * time.Second, RxBytes: 32},

			{when: 550 * time.Second, RxBytes: 32},
			{when: 575 * time.Second, RxBytes: 32},
			{when: 600 * time.Second, RxBytes: 32},
			{when: 600 * time.Second, RxBytes: 148},

			{when: 625 * time.Second, RxBytes: 32},
			{when: 650 * time.Second, RxBytes: 32},

			{when: 675 * time.Second, RxBytes: 32},
			{when: 700 * time.Second, RxBytes: 32},

			{when: 725 * time.Second, RxBytes: 32},
			{when: 725 * time.Second, RxBytes: 148},
			{when: 750 * time.Second, RxBytes: 32},
		},
	},
}
