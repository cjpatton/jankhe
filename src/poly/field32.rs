use lazy_static::lazy_static;
use prio::field::FieldPrio2 as Field32;

use crate::poly::NttParamD256;

lazy_static! {
    pub(crate) static ref POLY_MUL_FIELD32: NttParamD256<Field32> = NttParamD256 {
        num_levels: 7,
        ts: [
            // level 0
            Field32::from(37101870),
            // level 1
            Field32::from(741585712),
            Field32::from(3598607238),
            // level 2
            Field32::from(806554333),
            Field32::from(1951000133),
            Field32::from(2342252472),
            Field32::from(3453551898),
            // level 3
            Field32::from(3636360432),
            Field32::from(94600197),
            Field32::from(1061493678),
            Field32::from(1257999482),
            Field32::from(3814329721),
            Field32::from(1652941122),
            Field32::from(2310715122),
            Field32::from(968005177),
            // level 4
            Field32::from(1200391425),
            Field32::from(3128114347),
            Field32::from(3144662134),
            Field32::from(2338031628),
            Field32::from(2514265747),
            Field32::from(2035981459),
            Field32::from(1529924105),
            Field32::from(1062485934),
            Field32::from(2736287676),
            Field32::from(1199928303),
            Field32::from(2153873066),
            Field32::from(3007794534),
            Field32::from(3315127182),
            Field32::from(3286614862),
            Field32::from(3390200195),
            Field32::from(3256287785),
            // level 5
            Field32::from(3338450716),
            Field32::from(1412211970),
            Field32::from(2231294902),
            Field32::from(2332311142),
            Field32::from(1307269733),
            Field32::from(450697235),
            Field32::from(244348247),
            Field32::from(3758156457),
            Field32::from(1053258481),
            Field32::from(92087675),
            Field32::from(1333826233),
            Field32::from(111519058),
            Field32::from(2082220453),
            Field32::from(2275854045),
            Field32::from(2376732840),
            Field32::from(233092547),
            Field32::from(2540865360),
            Field32::from(3755564905),
            Field32::from(1911658643),
            Field32::from(1662364995),
            Field32::from(2466944101),
            Field32::from(343904673),
            Field32::from(2547492843),
            Field32::from(2998429760),
            Field32::from(2336372591),
            Field32::from(1199490242),
            Field32::from(1872953394),
            Field32::from(2071622990),
            Field32::from(3534174188),
            Field32::from(2476244411),
            Field32::from(493424184),
            Field32::from(3662366743),
            // level 6
            Field32::from(732210571),
            Field32::from(1387388861),
            Field32::from(2211011159),
            Field32::from(2051411929),
            Field32::from(2128038472),
            Field32::from(455471368),
            Field32::from(3375478641),
            Field32::from(1095926402),
            Field32::from(1203602651),
            Field32::from(4001273314),
            Field32::from(2559888380),
            Field32::from(1266769554),
            Field32::from(1633449874),
            Field32::from(1907625545),
            Field32::from(2335775177),
            Field32::from(1167616620),
            Field32::from(605652300),
            Field32::from(3790805617),
            Field32::from(3133861573),
            Field32::from(1971380815),
            Field32::from(1783028302),
            Field32::from(3416771867),
            Field32::from(431182099),
            Field32::from(1862980846),
            Field32::from(3608602060),
            Field32::from(4080480150),
            Field32::from(3607689144),
            Field32::from(246443101),
            Field32::from(823425083),
            Field32::from(2991413966),
            Field32::from(290531752),
            Field32::from(1919035878),
            Field32::from(1861358601),
            Field32::from(33203794),
            Field32::from(428353847),
            Field32::from(515308288),
            Field32::from(2391297049),
            Field32::from(457728520),
            Field32::from(2669609004),
            Field32::from(1994409282),
            Field32::from(2324680219),
            Field32::from(4044880694),
            Field32::from(3175721955),
            Field32::from(1039896012),
            Field32::from(667150930),
            Field32::from(733169939),
            Field32::from(2928991398),
            Field32::from(3708624912),
            Field32::from(3663542477),
            Field32::from(3790758596),
            Field32::from(3477962022),
            Field32::from(1159211526),
            Field32::from(3379248674),
            Field32::from(224001267),
            Field32::from(2679495740),
            Field32::from(2195191829),
            Field32::from(3912533879),
            Field32::from(1246964281),
            Field32::from(4238346518),
            Field32::from(229463435),
            Field32::from(2101696342),
            Field32::from(3898167658),
            Field32::from(3551465356),
            Field32::from(735471256),
        ],
        us: [
            // level 0
            Field32::from(4256816851),
            // level 1
            Field32::from(3552333009),
            Field32::from(695311483),
            // level 2
            Field32::from(3487364388),
            Field32::from(2342918588),
            Field32::from(1951666249),
            Field32::from(840366823),
            // level 3
            Field32::from(657558289),
            Field32::from(4199318524),
            Field32::from(3232425043),
            Field32::from(3035919239),
            Field32::from(479589000),
            Field32::from(2640977599),
            Field32::from(1983203599),
            Field32::from(3325913544),
            // level 4
            Field32::from(3093527296),
            Field32::from(1165804374),
            Field32::from(1149256587),
            Field32::from(1955887093),
            Field32::from(1779652974),
            Field32::from(2257937262),
            Field32::from(2763994616),
            Field32::from(3231432787),
            Field32::from(1557631045),
            Field32::from(3093990418),
            Field32::from(2140045655),
            Field32::from(1286124187),
            Field32::from(978791539),
            Field32::from(1007303859),
            Field32::from(903718526),
            Field32::from(1037630936),
            // level 5
            Field32::from(955468005),
            Field32::from(2881706751),
            Field32::from(2062623819),
            Field32::from(1961607579),
            Field32::from(2986648988),
            Field32::from(3843221486),
            Field32::from(4049570474),
            Field32::from(535762264),
            Field32::from(3240660240),
            Field32::from(4201831046),
            Field32::from(2960092488),
            Field32::from(4182399663),
            Field32::from(2211698268),
            Field32::from(2018064676),
            Field32::from(1917185881),
            Field32::from(4060826174),
            Field32::from(1753053361),
            Field32::from(538353816),
            Field32::from(2382260078),
            Field32::from(2631553726),
            Field32::from(1826974620),
            Field32::from(3950014048),
            Field32::from(1746425878),
            Field32::from(1295488961),
            Field32::from(1957546130),
            Field32::from(3094428479),
            Field32::from(2420965327),
            Field32::from(2222295731),
            Field32::from(759744533),
            Field32::from(1817674310),
            Field32::from(3800494537),
            Field32::from(631551978),
            // level 6
            Field32::from(3561708150),
            Field32::from(2906529860),
            Field32::from(2082907562),
            Field32::from(2242506792),
            Field32::from(2165880249),
            Field32::from(3838447353),
            Field32::from(918440080),
            Field32::from(3197992319),
            Field32::from(3090316070),
            Field32::from(292645407),
            Field32::from(1734030341),
            Field32::from(3027149167),
            Field32::from(2660468847),
            Field32::from(2386293176),
            Field32::from(1958143544),
            Field32::from(3126302101),
            Field32::from(3688266421),
            Field32::from(503113104),
            Field32::from(1160057148),
            Field32::from(2322537906),
            Field32::from(2510890419),
            Field32::from(877146854),
            Field32::from(3862736622),
            Field32::from(2430937875),
            Field32::from(685316661),
            Field32::from(213438571),
            Field32::from(686229577),
            Field32::from(4047475620),
            Field32::from(3470493638),
            Field32::from(1302504755),
            Field32::from(4003386969),
            Field32::from(2374882843),
            Field32::from(2432560120),
            Field32::from(4260714927),
            Field32::from(3865564874),
            Field32::from(3778610433),
            Field32::from(1902621672),
            Field32::from(3836190201),
            Field32::from(1624309717),
            Field32::from(2299509439),
            Field32::from(1969238502),
            Field32::from(249038027),
            Field32::from(1118196766),
            Field32::from(3254022709),
            Field32::from(3626767791),
            Field32::from(3560748782),
            Field32::from(1364927323),
            Field32::from(585293809),
            Field32::from(630376244),
            Field32::from(503160125),
            Field32::from(815956699),
            Field32::from(3134707195),
            Field32::from(914670047),
            Field32::from(4069917454),
            Field32::from(1614422981),
            Field32::from(2098726892),
            Field32::from(381384842),
            Field32::from(3046954440),
            Field32::from(55572203),
            Field32::from(4064455286),
            Field32::from(2192222379),
            Field32::from(395751063),
            Field32::from(742453365),
            Field32::from(3558447465),
        ],
        c: Field32::from(4260372481), // 2^-7
    };
}

#[cfg(test)]
mod tests {
    use crate::poly::Rq;

    use super::*;

    #[test]
    fn poly_mol_test_field32() {
        {
            let a = Rq([Field32::from(0); 256]);
            let b = Rq([Field32::from(0); 256]);
            let r = Rq([Field32::from(0); 256]);
            assert_eq!(r, POLY_MUL_FIELD32.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field32::from(0); 256]);
            a.0[7] = Field32::from(23);
            let b = Rq([Field32::from(0); 256]);
            let r = Rq([Field32::from(0); 256]);
            assert_eq!(r, POLY_MUL_FIELD32.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field32::from(0); 256]);
            a.0[7] = Field32::from(23);
            let mut b = Rq([Field32::from(0); 256]);
            b.0[0] = Field32::from(1);
            let mut r = Rq([Field32::from(0); 256]);
            r.0[7] = Field32::from(23);
            assert_eq!(r, POLY_MUL_FIELD32.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field32::from(0); 256]);
            a.0[7] = Field32::from(23);
            let mut b = Rq([Field32::from(0); 256]);
            b.0[2] = Field32::from(1);
            let mut r = Rq([Field32::from(0); 256]);
            r.0[9] = Field32::from(23);
            assert_eq!(r, POLY_MUL_FIELD32.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field32::from(0); 256]);
            a.0[255] = Field32::from(23);
            let mut b = Rq([Field32::from(0); 256]);
            b.0[1] = Field32::from(1);
            let mut r = Rq([Field32::from(0); 256]);
            r.0[0] = -Field32::from(23);
            assert_eq!(r, POLY_MUL_FIELD32.poly_mul(&a, &b));
        }
    }
}
