#![allow(dead_code)] // XXX Remove me

use bitvec::prelude::*;
use lazy_static::lazy_static;
use prio::field::{Field128, FieldElement, FieldElementWithInteger};
use rand::prelude::*;
use std::{
    array::from_fn,
    ops::{Add, Mul, Neg},
};

/// Polynomial ring for the ciphertext.
///
/// NOTE: SEAL uses a composite modulus for the ciphertext. It recommends safe defaults based on the
/// size of the plaintext modulus. It also allows the user to choose the modulus themselves. For
/// now, we're hardcoding a prime modulus for which we know how to implement NTT.
#[derive(Clone, Debug, PartialEq)]
pub struct Cr<F: FieldElement, const D: usize>(pub(crate) [F; D]);

impl<F: FieldElement + FieldElementWithInteger, const D: usize> Cr<F, D> {
    pub(crate) fn rand_long() -> Self {
        // TODO Implement `Distribution<Cr<F,D>>` for `Standard` instead. This will require changes
        // upstream in `prio`.
        Self(prio::field::random_vector(D).try_into().unwrap())
    }

    /// Sample a polynomial with binomially distributed coefficients.
    pub(crate) fn rand_short() -> Self {
        const ETA: usize = 3;
        const BYTES_BUF_SIZE: usize = 256;

        let mut rng = thread_rng();
        let bits_sampled = 2 * ETA * D;
        let bytes_sampled = (bits_sampled + 7) / 8;
        debug_assert!(bytes_sampled <= BYTES_BUF_SIZE);
        let mut bytes = [0_u8; BYTES_BUF_SIZE];
        rng.fill(&mut bytes[..bytes_sampled]);

        let mut bits = bytes[..bytes_sampled].view_bits::<Msb0>().chunks(2);
        let mut sample = || {
            let chunk = bits.next().unwrap();
            let value = chunk.load_be::<usize>();
            F::from(F::Integer::try_from(value).unwrap())
        };

        Self(from_fn(|_| sample() - sample()))
    }
}

impl<F: FieldElement, const D: usize> Add for &Cr<F, D> {
    type Output = Cr<F, D>;
    fn add(self, rhs: Self) -> Self::Output {
        Cr(from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl Mul for &Cr<Field128, 256> {
    type Output = Cr<Field128, 256>;
    fn mul(self, rhs: Self) -> Self::Output {
        POLY_MUL_FIELD_128.poly_mul(self, rhs)
    }
}

impl<F: FieldElement, const D: usize> Neg for &Cr<F, D> {
    type Output = Cr<F, D>;
    fn neg(self) -> Self::Output {
        Cr(from_fn(|i| -self.0[i]))
    }
}

// XXX Generalize D
struct NttParamD256<F: FieldElement> {
    num_levels: usize,
    ts: [F; 127],
    us: [F; 127],
    c: F,
}

impl<F: FieldElement> NttParamD256<F> {
    /// Multiply two polynomials `a` and `b` from `F[X]/(X^256 + 1)`.
    fn poly_mul(&self, Cr(a): &Cr<F, 256>, Cr(b): &Cr<F, 256>) -> Cr<F, 256> {
        fn level<F>(t: &[F], i: usize) -> &[F] {
            let level_start = (1 << i) - 1;
            let level_len = 1 << i;
            &t[level_start..level_start + level_len]
        }

        debug_assert_eq!(self.ts.len(), self.us.len());

        let (mut p, mut n) = (0, 1);
        let mut ntt_a = [*a, [F::zero(); 256]];
        let mut ntt_b = [*b, [F::zero(); 256]];

        for i in 0..self.num_levels {
            let t = level(&self.ts, i);
            let v = 1 << (8 - i); // width
            let w = v / 2; // split
            debug_assert_eq!(256 / v, t.len());
            for (j, z) in (0..256).step_by(v).zip(t.iter().copied()) {
                for k in j..j + w {
                    // a
                    let y = z * ntt_a[p][k + w];
                    ntt_a[n][k] = ntt_a[p][k] + y;
                    ntt_a[n][k + w] = ntt_a[p][k] - y;

                    // b
                    let y = z * ntt_b[p][k + w];
                    ntt_b[n][k] = ntt_b[p][k] + y;
                    ntt_b[n][k + w] = ntt_b[p][k] - y;
                }
            }
            (p, n) = (1 - p, 1 - n);
        }

        for i in 0..64 {
            let range = 4 * i..4 * i + 2;
            let ntt_x: [_; 2] = slow_poly_mul(
                ntt_a[p][range.clone()].try_into().unwrap(),
                ntt_b[p][range.clone()].try_into().unwrap(),
                level(&self.us, self.num_levels - 1)[i],
            );
            ntt_a[n][range.clone()].copy_from_slice(&ntt_x);

            let range = 4 * i + 2..4 * i + 4;
            let ntt_x: [_; 2] = slow_poly_mul(
                ntt_a[p][range.clone()].try_into().unwrap(),
                ntt_b[p][range.clone()].try_into().unwrap(),
                level(&self.ts, self.num_levels - 1)[i],
            );
            ntt_a[n][range.clone()].copy_from_slice(&ntt_x);
        }
        (p, n) = (1 - p, 1 - n);

        for i in (0..self.num_levels).rev() {
            let u = level(&self.us, i);
            let v = 1 << (8 - i); // width
            let w = v / 2; // split
            debug_assert_eq!(256 / v, u.len());
            for (j, z) in (0..256).step_by(v).zip(u.iter().copied().rev()) {
                for k in j..j + w {
                    // a
                    ntt_a[n][k] = ntt_a[p][k] + ntt_a[p][k + w];
                    ntt_a[n][k + w] = (ntt_a[p][k] - ntt_a[p][k + w]) * z;
                }
            }
            (p, n) = (1 - p, 1 - n);
        }

        // Multiply each element of the output by `2^-7`. See [Lyu24], bottom of Section 4.6.
        for i in 0..256 {
            ntt_a[p][i] *= self.c;
        }

        Cr(ntt_a[p])
    }
}

/// Multiply two polynomials `a` and `b` from `F[X]/(X^D + r)`.
///
/// This is the algorithm described in Section 4.1.1 of [Lyu24]. Matrix `m` is the transpose
/// of the matrix on the left hand side of Equation (43).
fn slow_poly_mul<F: FieldElement, const D: usize>(mut a: [F; D], b: [F; D], r: F) -> [F; D] {
    let m: Mat<F, D, D> = Mat(from_fn(|_| {
        let row = a;

        // Multiply `a` by `X` and reduce.
        //
        // Let `c` be the leading coefficient of `a`.
        let c = a[D - 1];

        // Multiply `a` by `X` in place by shifting everything over.
        for j in (1..D).rev() {
            a[j] = a[j - 1];
        }

        // Clear the first coefficient of `a` to complete the shift and subtract `c * F(X)` from `a`.
        a[0] = r * -c;

        row
    }));

    (&Mat([b]) * &m).0[0]
}

struct Mat<F, const ROWS: usize, const COLS: usize>([[F; COLS]; ROWS]);

impl<F: FieldElement, const I: usize, const J: usize, const K: usize> Mul<&Mat<F, J, K>>
    for &Mat<F, I, J>
{
    type Output = Mat<F, I, K>;
    fn mul(self, rhs: &Mat<F, J, K>) -> Mat<F, I, K> {
        let mut out = [[F::zero(); K]; I];
        for i in 0..I {
            for j in 0..J {
                for k in 0..K {
                    out[i][k] += self.0[i][j] * rhs.0[j][k];
                }
            }
        }
        Mat(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slow_poly_mul() {
        assert_eq!(
            [Field128::from(0), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(99), Field128::from(99)],
                [Field128::from(0), Field128::from(0)],
                Field128::one(),
            )
        );

        assert_eq!(
            [Field128::from(1), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(1), Field128::from(0)],
                [Field128::from(1), Field128::from(0)],
                Field128::one(),
            )
        );

        assert_eq!(
            [Field128::from(0), Field128::from(1)],
            slow_poly_mul(
                [Field128::from(1), Field128::from(0)],
                [Field128::from(0), Field128::from(1)],
                Field128::one(),
            )
        );

        assert_eq!(
            [Field128::from(0), Field128::from(6)],
            slow_poly_mul(
                [Field128::from(2), Field128::from(0)],
                [Field128::from(0), Field128::from(3)],
                Field128::one(),
            )
        );

        assert_eq!(
            [-Field128::from(6), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(0), Field128::from(2)],
                [Field128::from(0), Field128::from(3)],
                Field128::one(),
            )
        );

        assert_eq!(
            [-Field128::from(12), Field128::from(0)],
            slow_poly_mul(
                [Field128::from(0), Field128::from(2)],
                [Field128::from(0), Field128::from(3)],
                Field128::from(2),
            )
        );
    }

    #[test]
    fn test_ntt_poly_mol() {
        {
            let a = Cr([Field128::from(0); 256]);
            let b = Cr([Field128::from(0); 256]);
            let r = Cr([Field128::from(0); 256]);
            assert_eq!(r, POLY_MUL_FIELD_128.poly_mul(&a, &b));
        }

        {
            let mut a = Cr([Field128::from(0); 256]);
            a.0[7] = Field128::from(23);
            let b = Cr([Field128::from(0); 256]);
            let r = Cr([Field128::from(0); 256]);
            assert_eq!(r, POLY_MUL_FIELD_128.poly_mul(&a, &b));
        }

        {
            let mut a = Cr([Field128::from(0); 256]);
            a.0[7] = Field128::from(23);
            let mut b = Cr([Field128::from(0); 256]);
            b.0[0] = Field128::from(1);
            let mut r = Cr([Field128::from(0); 256]);
            r.0[7] = Field128::from(23);
            assert_eq!(r, POLY_MUL_FIELD_128.poly_mul(&a, &b));
        }

        {
            let mut a = Cr([Field128::from(0); 256]);
            a.0[7] = Field128::from(23);
            let mut b = Cr([Field128::from(0); 256]);
            b.0[2] = Field128::from(1);
            let mut r = Cr([Field128::from(0); 256]);
            r.0[9] = Field128::from(23);
            assert_eq!(r, POLY_MUL_FIELD_128.poly_mul(&a, &b));
        }

        {
            let mut a = Cr([Field128::from(0); 256]);
            a.0[255] = Field128::from(23);
            let mut b = Cr([Field128::from(0); 256]);
            b.0[1] = Field128::from(1);
            let mut r = Cr([Field128::from(0); 256]);
            r.0[0] = -Field128::from(23);
            assert_eq!(r, POLY_MUL_FIELD_128.poly_mul(&a, &b));
        }
    }
}

lazy_static! {
    static ref POLY_MUL_FIELD_128: NttParamD256<Field128> = NttParamD256 {
        num_levels: 7,
        ts: [
            // level 0
            Field128::from(43482856138516670506292376531135147170),
            // level 1
            Field128::from(200810852397338366995356413323740658916),
            Field128::from(318105318622626656116822425073164958506),
            // level 2
            Field128::from(62304660289062950672806460965150310637),
            Field128::from(133199926836900963745501693426240858618),
            Field128::from(227101476958844824561225924334879330359),
            Field128::from(145297613515289394570967514889626843620),
            // level 3
            Field128::from(175514189579196055294699063096378878741),
            Field128::from(193241761787407685671448823696396603028),
            Field128::from(3223362179881897295227655658778263782),
            Field128::from(303710393730255557202314943704058840521),
            Field128::from(297325971661524596413420739402760013437),
            Field128::from(307956641479908342626109376394091522974),
            Field128::from(220514489592186641893040849599624056427),
            Field128::from(66744898958981417258026933589281269838),
            // level 4
            Field128::from(269190794366931664401273698877920593800),
            Field128::from(251829672794901955881440267550020778066),
            Field128::from(37520094761489950374065048257728074633),
            Field128::from(284070256442392700407900194265859996994),
            Field128::from(74074713926469487582053960025397862471),
            Field128::from(230793090856856623076904468700330579712),
            Field128::from(43478321202485846568448897872644365826),
            Field128::from(68157169904682515586789403413049213293),
            Field128::from(95849793411460597687269635626457329983),
            Field128::from(48956946827392556551586558983134383524),
            Field128::from(84284646567543607338029534804727636963),
            Field128::from(18731266374118080045090665182143197049),
            Field128::from(176966694186116925710657732206645102855),
            Field128::from(284622066638003875853256413067936714441),
            Field128::from(164118169684073674497830130095400509465),
            Field128::from(70540665634008446339933661952879097528),
            // level 5
            Field128::from(151959974497288354769135760032128419854),
            Field128::from(190443686694029988148898454026969178891),
            Field128::from(232035515901792875916444659018678903449),
            Field128::from(245654529611547633470004443550894428066),
            Field128::from(285130048147413316117964856344935628393),
            Field128::from(328104821221029688678473334341885183517),
            Field128::from(45553693248314463302123895407062989867),
            Field128::from(69029183923062659558564327151412908118),
            Field128::from(79094028423774171969654390013417041025),
            Field128::from(61570051180692132992860993531593692163),
            Field128::from(153590084854475035827119139857603778639),
            Field128::from(328552439051355368601789529229627444455),
            Field128::from(77679139310187886764740630057397104542),
            Field128::from(146218582625113096785905194355581654507),
            Field128::from(210881836176966975666809431435754146389),
            Field128::from(202684864785552694015839950675495720827),
            Field128::from(239850899718548955786841713006009083963),
            Field128::from(98612381221215872413223431184410842806),
            Field128::from(322047717392718813256445494920061102434),
            Field128::from(192620203719053212448820753271933477680),
            Field128::from(89780080949520314047327938924293118477),
            Field128::from(44331924744845938630339355211875279187),
            Field128::from(172453765236522985331418295202396999555),
            Field128::from(186471368372746529704548464519299549342),
            Field128::from(108380279390508469765584057087490434976),
            Field128::from(51278998164551975672740962339320715182),
            Field128::from(60549559286267026950505296062343839642),
            Field128::from(163716795238535047499138723689128628212),
            Field128::from(260531347873685204078023196853724371639),
            Field128::from(326454839187362594980604966220520881005),
            Field128::from(292434311472248662242922010064360782556),
            Field128::from(303892309822896297917577954255934761642),
            // level 6
            Field128::from(143141298024093847701129645446100165914),
            Field128::from(13920092502624681902843427268694720857),
            Field128::from(67959010433230547290700909527930504241),
            Field128::from(292877036352528914108831604156641445839),
            Field128::from(311181405809507705139733701622304301363),
            Field128::from(124194953721043414638257464731245445690),
            Field128::from(223862230768675162891827897755394374997),
            Field128::from(340040045452600922988441702066160304551),
            Field128::from(76449783086224685836427401378538833924),
            Field128::from(107001637307749702198270851386321731916),
            Field128::from(50408491163569193191686561467666247475),
            Field128::from(157511130200018181475778295761918503100),
            Field128::from(239413597772741505894742650959457018945),
            Field128::from(22573265209257073197528426158174721829),
            Field128::from(227985114746248297529827176930554697942),
            Field128::from(156924421586739699236221700370855811746),
            Field128::from(205569472030554573297821451271061745425),
            Field128::from(33466720600476368345632746616496309481),
            Field128::from(158616870077459072512988914230846539267),
            Field128::from(282664279706928174903656331886493683208),
            Field128::from(128512927994809700040202485148354773638),
            Field128::from(163767633415028686338346716217674111540),
            Field128::from(131435433489365892170491395273851546789),
            Field128::from(43782295651249599967808705405001894664),
            Field128::from(269858926025490866213843008908542483600),
            Field128::from(205576661379309887032985086071871002482),
            Field128::from(228049779715677751617363805664050187895),
            Field128::from(21967595685277265286968962759244249238),
            Field128::from(312086086339083912533691252263246680459),
            Field128::from(7963628438012743260246090488962710745),
            Field128::from(223395444765789228238745556766411549120),
            Field128::from(194201839079613979888246574558494000021),
            Field128::from(307033699912965774744631512378410709982),
            Field128::from(164878166819378564133454792195044992384),
            Field128::from(127588711240553479300870097598083149493),
            Field128::from(238010459756044217452766532923994167075),
            Field128::from(106231143425809964959466815155440859170),
            Field128::from(223772822021257446265330431823789263730),
            Field128::from(312185733035220518387228816520830273648),
            Field128::from(165926006135617399780874764149083068513),
            Field128::from(172567455156426938130197499343176422692),
            Field128::from(264965818991908427518981306617801599446),
            Field128::from(268888458342799703173204434397875850850),
            Field128::from(123268836554971170273847197810647784542),
            Field128::from(233473594226833253302660057755875919720),
            Field128::from(265792472897245853309474906517760791065),
            Field128::from(296126221500251693127995278361883763557),
            Field128::from(311321527462867399833352727041586330128),
            Field128::from(53504784204520595718008386737507450110),
            Field128::from(205208545780493947155570860511279515054),
            Field128::from(280489202627461452563686475100013253100),
            Field128::from(323088361605170835381043026578600248164),
            Field128::from(8020183223747875468530665746174954134),
            Field128::from(251293482976085236561896797434127610866),
            Field128::from(229925669019152714137161754650625638956),
            Field128::from(43971509134914332523514937239034085972),
            Field128::from(264366980677663156116541300923071668487),
            Field128::from(59976323871489257039092588437105451501),
            Field128::from(29293281647131742449518602648991009199),
            Field128::from(267081327632869358499583370115605153765),
            Field128::from(301579289694095791529802093483991420746),
            Field128::from(182191026459149069380742002263599507294),
            Field128::from(275594812483824612182955066786446335256),
            Field128::from(210966142916779246805155704093159082429),
        ],
        us: [
            // level 0
            Field128::from(296799510782421792440573396836765619039),
            // level 1
            Field128::from(139471514523600095951509360044160107293),
            Field128::from(22177048298311806830043348294735807703),
            // level 2
            Field128::from(277977706631875512274059312402750455572),
            Field128::from(207082440084037499201364079941659907591),
            Field128::from(113180889962093638385639849033021435850),
            Field128::from(194984753405649068375898258478273922589),
            // level 3
            Field128::from(164768177341742407652166710271521887468),
            Field128::from(147040605133530777275416949671504163181),
            Field128::from(337059004741056565651638117709122502427),
            Field128::from(36571973190682905744550829663841925688),
            Field128::from(42956395259413866533445033965140752772),
            Field128::from(32325725441030120320756396973809243235),
            Field128::from(119767877328751821053824923768276709782),
            Field128::from(273537467961957045688838839778619496371),
            // level 4
            Field128::from(71091572554006798545592074489980172409),
            Field128::from(88452694126036507065425505817879988143),
            Field128::from(302762272159448512572800725110172691576),
            Field128::from(56212110478545762538965579102040769215),
            Field128::from(266207652994468975364811813342502903738),
            Field128::from(109489276064081839869961304667570186497),
            Field128::from(296804045718452616378416875495256400383),
            Field128::from(272125197016255947360076369954851552916),
            Field128::from(244432573509477865259596137741443436226),
            Field128::from(291325420093545906395279214384766382685),
            Field128::from(255997720353394855608836238563173129246),
            Field128::from(321551100546820382901775108185757569160),
            Field128::from(163315672734821537236208041161255663354),
            Field128::from(55660300282934587093609360299964051768),
            Field128::from(176164197236864788449035643272500256744),
            Field128::from(269741701286930016606932111415021668681),
            // level 5
            Field128::from(188322392423650108177730013335772346355),
            Field128::from(149838680226908474797967319340931587318),
            Field128::from(108246851019145587030421114349221862760),
            Field128::from(94627837309390829476861329817006338143),
            Field128::from(55152318773525146828900917022965137816),
            Field128::from(12177545699908774268392439026015582692),
            Field128::from(294728673672623999644741877960837776342),
            Field128::from(271253182997875803388301446216487858091),
            Field128::from(261188338497164290977211383354483725184),
            Field128::from(278712315740246329954004779836307074046),
            Field128::from(186692282066463427119746633510296987570),
            Field128::from(11729927869583094345076244138273321754),
            Field128::from(262603227610750576182125143310503661667),
            Field128::from(194063784295825366160960579012319111702),
            Field128::from(129400530743971487280056341932146619820),
            Field128::from(137597502135385768931025822692405045382),
            Field128::from(100431467202389507160024060361891682246),
            Field128::from(241669985699722590533642342183489923403),
            Field128::from(18234649528219649690420278447839663775),
            Field128::from(147662163201885250498045020095967288529),
            Field128::from(250502285971418148899537834443607647732),
            Field128::from(295950442176092524316526418156025487022),
            Field128::from(167828601684415477615447478165503766654),
            Field128::from(153810998548191933242317308848601216867),
            Field128::from(231902087530429993181281716280410331233),
            Field128::from(289003368756386487274124811028580051027),
            Field128::from(279732807634671435996360477305556926567),
            Field128::from(176565571682403415447727049678772137997),
            Field128::from(79751019047253258868842576514176394570),
            Field128::from(13827527733575867966260807147379885204),
            Field128::from(47848055448689800703943763303539983653),
            Field128::from(36390057098042165029287819111966004567),
            // level 6
            Field128::from(197141068896844615245736127921800600295),
            Field128::from(326362274418313781044022346099206045352),
            Field128::from(272323356487707915656164863839970261968),
            Field128::from(47405330568409548838034169211259320370),
            Field128::from(29100961111430757807132071745596464846),
            Field128::from(216087413199895048308608308636655320519),
            Field128::from(116420136152263300055037875612506391212),
            Field128::from(242321468337539958424071301740461658),
            Field128::from(263832583834713777110438371989361932285),
            Field128::from(233280729613188760748594921981579034293),
            Field128::from(289873875757369269755179211900234518734),
            Field128::from(182771236720920281471087477605982263109),
            Field128::from(100868769148196957052123122408443747264),
            Field128::from(317709101711681389749337347209726044380),
            Field128::from(112297252174690165417038596437346068267),
            Field128::from(183357945334198763710644072997044954463),
            Field128::from(134712894890383889649044322096839020784),
            Field128::from(306815646320462094601233026751404456728),
            Field128::from(181665496843479390433876859137054226942),
            Field128::from(57618087214010288043209441481407083001),
            Field128::from(211769438926128762906663288219545992571),
            Field128::from(176514733505909776608519057150226654669),
            Field128::from(208846933431572570776374378094049219420),
            Field128::from(296500071269688862979057067962898871545),
            Field128::from(70423440895447596733022764459358282609),
            Field128::from(134705705541628575913880687296029763727),
            Field128::from(112232587205260711329501967703850578314),
            Field128::from(318314771235661197659896810608656516971),
            Field128::from(28196280581854550413174521104654085750),
            Field128::from(332318738482925719686619682878938055464),
            Field128::from(116886922155149234708120216601489217089),
            Field128::from(146080527841324483058619198809406766188),
            Field128::from(33248667007972688202234260989490056227),
            Field128::from(175404200101559898813410981172855773825),
            Field128::from(212693655680384983645995675769817616716),
            Field128::from(102271907164894245494099240443906599134),
            Field128::from(234051223495128497987398958212459907039),
            Field128::from(116509544899681016681535341544111502479),
            Field128::from(28096633885717944559636956847070492561),
            Field128::from(174356360785321063165991009218817697696),
            Field128::from(167714911764511524816668274024724343517),
            Field128::from(75316547929030035427884466750099166763),
            Field128::from(71393908578138759773661338970024915359),
            Field128::from(217013530365967292673018575557252981667),
            Field128::from(106808772694105209644205715612024846489),
            Field128::from(74489894023692609637390866850139975144),
            Field128::from(44156145420686769818870495006017002652),
            Field128::from(28960839458071063113513046326314436081),
            Field128::from(286777582716417867228857386630393316099),
            Field128::from(135073821140444515791294912856621251155),
            Field128::from(59793164293477010383179298267887513109),
            Field128::from(17194005315767627565822746789300518045),
            Field128::from(332262183697190587478335107621725812075),
            Field128::from(88988883944853226384968975933773155343),
            Field128::from(110356697901785748809704018717275127253),
            Field128::from(296310857786024130423350836128866680237),
            Field128::from(75915386243275306830324472444829097722),
            Field128::from(280306043049449205907773184930795314708),
            Field128::from(310989085273806720497347170718909757010),
            Field128::from(73201039288069104447282403252295612444),
            Field128::from(38703077226842671417063679883909345463),
            Field128::from(158091340461789393566123771104301258915),
            Field128::from(64687554437113850763910706581454430953),
            Field128::from(129316224004159216141710069274741683780),
        ],
        c: Field128::from(337623910929368631205093384513464041473), // 2^-7
    };
}
