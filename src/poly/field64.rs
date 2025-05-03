use lazy_static::lazy_static;
use prio::field::Field64;

use crate::poly::NttParamD256;

lazy_static! {
    pub(crate) static ref POLY_MUL_FIELD64: NttParamD256<Field64> = NttParamD256 {
        num_levels: 7,
        ts: [
            // level 0
            Field64::from(18446462594437873665),
            // level 1
            Field64::from(16777216),
            Field64::from(1099511627520),
            // level 2
            Field64::from(1152921504606846976),
            Field64::from(18446744069414580225),
            Field64::from(18442240469788262401),
            Field64::from(68719476736),
            // level 3
            Field64::from(18446673700670423041),
            Field64::from(1073741824),
            Field64::from(18446744069414584257),
            Field64::from(18428729670905102337),
            Field64::from(18446739671368073217),
            Field64::from(18158513693329981441),
            Field64::from(17179869180),
            Field64::from(18446744069414322177),
            // level 4
            Field64::from(18446743519658770433),
            Field64::from(18410715272404008961),
            Field64::from(9223372036854775808),
            Field64::from(18446744069414551553),
            Field64::from(18446744069414584313),
            Field64::from(18444492269600899073),
            Field64::from(134217728),
            Field64::from(8796093020160),
            Field64::from(2097152),
            Field64::from(137438953440),
            Field64::from(18446708885042495489),
            Field64::from(16140901060737761281),
            Field64::from(18446181119461294081),
            Field64::from(8589934592),
            Field64::from(18446744069414583809),
            Field64::from(18302628881338728449),
            // level 5
            Field64::from(576451956076183552),
            Field64::from(17870274521152356353),
            Field64::from(34360262648),
            Field64::from(34359214072),
            Field64::from(36028797018963840),
            Field64::from(18410715272395620225),
            Field64::from(18446603334073745409),
            Field64::from(140739635806208),
            Field64::from(18446741870424883713),
            Field64::from(2199056809472),
            Field64::from(18446181119461163007),
            Field64::from(18446181119461163011),
            Field64::from(18437736732722987009),
            Field64::from(18437737007600893953),
            Field64::from(2305843009213685760),
            Field64::from(16140901060200882177),
            Field64::from(18445618152328134657),
            Field64::from(18445618186687873025),
            Field64::from(288230376151710720),
            Field64::from(18158513693262871553),
            Field64::from(4611615648609468416),
            Field64::from(13834987683316760577),
            Field64::from(274882101184),
            Field64::from(274873712576),
            Field64::from(4295032831),
            Field64::from(4294901759),
            Field64::from(18374685375881805825),
            Field64::from(18374687574905061377),
            Field64::from(18446726477496979457),
            Field64::from(17592454475776),
            Field64::from(18442240469787213809),
            Field64::from(18442240469787213841),
            // level 6
            Field64::from(4649662884198176411),
            Field64::from(4782006911144666502),
            Field64::from(4442103655964903148),
            Field64::from(912371727122717978),
            Field64::from(3341893669734556710),
            Field64::from(7979294039879560184),
            Field64::from(7614451796507779275),
            Field64::from(6366922389463153702),
            Field64::from(15395185741804386692),
            Field64::from(7593472940535036657),
            Field64::from(2430519478049941168),
            Field64::from(10900537202625306992),
            Field64::from(16792080670893602455),
            Field64::from(7709569171718681254),
            Field64::from(10967010099451201909),
            Field64::from(12612728678098075109),
            Field64::from(4404853092538523347),
            Field64::from(5575382163818481237),
            Field64::from(8288405288461869359),
            Field64::from(8494120110792728509),
            Field64::from(303814934756242646),
            Field64::from(1362567150328163374),
            Field64::from(17090085178304640863),
            Field64::from(7298973816981743824),
            Field64::from(9778634991702905054),
            Field64::from(13949104517951277988),
            Field64::from(5209436881246729393),
            Field64::from(6336321165505697069),
            Field64::from(12481021517947587610),
            Field64::from(5407551316036540293),
            Field64::from(997411754984945023),
            Field64::from(13417321343344118652),
            Field64::from(18165022998349842402),
            Field64::from(12109811546395398776),
            Field64::from(15155306912120837921),
            Field64::from(10265989416269385394),
            Field64::from(1506708620263852673),
            Field64::from(8215369291935911999),
            Field64::from(9083829225849678056),
            Field64::from(2843318466875884251),
            Field64::from(7059463857684370340),
            Field64::from(10708950766175242252),
            Field64::from(416595521271101505),
            Field64::from(264688053892980182),
            Field64::from(2495058814089251146),
            Field64::from(9516004302527281633),
            Field64::from(4195631349813649467),
            Field64::from(9274800740290006948),
            Field64::from(14146940403822094634),
            Field64::from(17330401598553671485),
            Field64::from(12053668962110821384),
            Field64::from(10382722127243543029),
            Field64::from(16192975500896648969),
            Field64::from(4644772024090268603),
            Field64::from(10561990880479197442),
            Field64::from(8340939052496745868),
            Field64::from(18035314424752866021),
            Field64::from(15118306729094611415),
            Field64::from(1513726443299424847),
            Field64::from(2341058142559915780),
            Field64::from(1135478653231209757),
            Field64::from(11884629851743600732),
            Field64::from(3332764170168812040),
            Field64::from(2117504431143841456),
        ],
        us: [
            // level 0
            Field64::from(281474976710656),
            // level 1
            Field64::from(18446744069397807105),
            Field64::from(18446742969902956801),
            // level 2
            Field64::from(17293822564807737345),
            Field64::from(4096),
            Field64::from(4503599626321920),
            Field64::from(18446744000695107585),
            // level 3
            Field64::from(70368744161280),
            Field64::from(18446744068340842497),
            Field64::from(64),
            Field64::from(18014398509481984),
            Field64::from(4398046511104),
            Field64::from(288230376084602880),
            Field64::from(18446744052234715141),
            Field64::from(262144),
            // level 4
            Field64::from(549755813888),
            Field64::from(36028797010575360),
            Field64::from(9223372032559808513),
            Field64::from(32768),
            Field64::from(8),
            Field64::from(2251799813685248),
            Field64::from(18446744069280366593),
            Field64::from(18446735273321564161),
            Field64::from(18446744069412487169),
            Field64::from(18446743931975630881),
            Field64::from(35184372088832),
            Field64::from(2305843008676823040),
            Field64::from(562949953290240),
            Field64::from(18446744060824649729),
            Field64::from(512),
            Field64::from(144115188075855872),
            // level 5
            Field64::from(17870292113338400769),
            Field64::from(576469548262227968),
            Field64::from(18446744035054321673),
            Field64::from(18446744035055370249),
            Field64::from(18410715272395620481),
            Field64::from(36028797018964096),
            Field64::from(140735340838912),
            Field64::from(18446603329778778113),
            Field64::from(2198989700608),
            Field64::from(18446741870357774849),
            Field64::from(562949953421314),
            Field64::from(562949953421310),
            Field64::from(9007336691597312),
            Field64::from(9007061813690368),
            Field64::from(16140901060200898561),
            Field64::from(2305843009213702144),
            Field64::from(1125917086449664),
            Field64::from(1125882726711296),
            Field64::from(18158513693262873601),
            Field64::from(288230376151712768),
            Field64::from(13835128420805115905),
            Field64::from(4611756386097823744),
            Field64::from(18446743794532483137),
            Field64::from(18446743794540871745),
            Field64::from(18446744065119551490),
            Field64::from(18446744065119682562),
            Field64::from(72058693532778496),
            Field64::from(72056494509522944),
            Field64::from(17591917604864),
            Field64::from(18446726476960108545),
            Field64::from(4503599627370512),
            Field64::from(4503599627370480),
            // level 6
            Field64::from(13797081185216407910),
            Field64::from(13664737158269917819),
            Field64::from(14004640413449681173),
            Field64::from(17534372342291866343),
            Field64::from(15104850399680027611),
            Field64::from(10467450029535024137),
            Field64::from(10832292272906805046),
            Field64::from(12079821679951430619),
            Field64::from(3051558327610197629),
            Field64::from(10853271128879547664),
            Field64::from(16016224591364643153),
            Field64::from(7546206866789277329),
            Field64::from(1654663398520981866),
            Field64::from(10737174897695903067),
            Field64::from(7479733969963382412),
            Field64::from(5834015391316509212),
            Field64::from(14041890976876060974),
            Field64::from(12871361905596103084),
            Field64::from(10158338780952714962),
            Field64::from(9952623958621855812),
            Field64::from(18142929134658341675),
            Field64::from(17084176919086420947),
            Field64::from(1356658891109943458),
            Field64::from(11147770252432840497),
            Field64::from(8668109077711679267),
            Field64::from(4497639551463306333),
            Field64::from(13237307188167854928),
            Field64::from(12110422903908887252),
            Field64::from(5965722551466996711),
            Field64::from(13039192753378044028),
            Field64::from(17449332314429639298),
            Field64::from(5029422726070465669),
            Field64::from(281721071064741919),
            Field64::from(6336932523019185545),
            Field64::from(3291437157293746400),
            Field64::from(8180754653145198927),
            Field64::from(16940035449150731648),
            Field64::from(10231374777478672322),
            Field64::from(9362914843564906265),
            Field64::from(15603425602538700070),
            Field64::from(11387280211730213981),
            Field64::from(7737793303239342069),
            Field64::from(18030148548143482816),
            Field64::from(18182056015521604139),
            Field64::from(15951685255325333175),
            Field64::from(8930739766887302688),
            Field64::from(14251112719600934854),
            Field64::from(9171943329124577373),
            Field64::from(4299803665592489687),
            Field64::from(1116342470860912836),
            Field64::from(6393075107303762937),
            Field64::from(8064021942171041292),
            Field64::from(2253768568517935352),
            Field64::from(13801972045324315718),
            Field64::from(7884753188935386879),
            Field64::from(10105805016917838453),
            Field64::from(411429644661718300),
            Field64::from(3328437340319972906),
            Field64::from(16933017626115159474),
            Field64::from(16105685926854668541),
            Field64::from(17311265416183374564),
            Field64::from(6562114217670983589),
            Field64::from(15113979899245772281),
            Field64::from(16329239638270742865),
        ],
        c: Field64::from(18302628881372282881), // 2^-7
    };
}

#[cfg(test)]
mod tests {
    use crate::poly::Rq;

    use super::*;

    #[test]
    fn poly_mol_test_field64() {
        {
            let a = Rq([Field64::from(0); 256]);
            let b = Rq([Field64::from(0); 256]);
            let r = Rq([Field64::from(0); 256]);
            assert_eq!(r, POLY_MUL_FIELD64.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field64::from(0); 256]);
            a.0[7] = Field64::from(23);
            let b = Rq([Field64::from(0); 256]);
            let r = Rq([Field64::from(0); 256]);
            assert_eq!(r, POLY_MUL_FIELD64.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field64::from(0); 256]);
            a.0[7] = Field64::from(23);
            let mut b = Rq([Field64::from(0); 256]);
            b.0[0] = Field64::from(1);
            let mut r = Rq([Field64::from(0); 256]);
            r.0[7] = Field64::from(23);
            assert_eq!(r, POLY_MUL_FIELD64.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field64::from(0); 256]);
            a.0[7] = Field64::from(23);
            let mut b = Rq([Field64::from(0); 256]);
            b.0[2] = Field64::from(1);
            let mut r = Rq([Field64::from(0); 256]);
            r.0[9] = Field64::from(23);
            assert_eq!(r, POLY_MUL_FIELD64.poly_mul(&a, &b));
        }

        {
            let mut a = Rq([Field64::from(0); 256]);
            a.0[255] = Field64::from(23);
            let mut b = Rq([Field64::from(0); 256]);
            b.0[1] = Field64::from(1);
            let mut r = Rq([Field64::from(0); 256]);
            r.0[0] = -Field64::from(23);
            assert_eq!(r, POLY_MUL_FIELD64.poly_mul(&a, &b));
        }
    }
}
