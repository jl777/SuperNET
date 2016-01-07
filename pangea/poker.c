// from http://www.azillionmonkeys.com/qed/poker.zip
// shamelessly copied from azillionmonkeys. getting millions of evals per second!

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#define CLUB_SUIT              (1)
#define DIAMOND_SUIT           (2)
#define HEART_SUIT             (4)
#define SPADE_SUIT             (8)

#define RANK_SHL              (27)
#define SUBR_SHL              (13)
#define SUBR_SHLMASK          ((1<<SUBR_SHL)-1)

#define STRAIGHT_FLUSH_SCORE  (8 << RANK_SHL)
#define FOUR_KIND_SCORE       (7 << RANK_SHL)
#define FULL_HOUSE_SCORE      (6 << RANK_SHL)
#define FLUSH_SCORE           (5 << RANK_SHL)
#define STRAIGHT_SCORE        (4 << RANK_SHL)
#define THREE_KIND_SCORE      (3 << RANK_SHL)
#define TWO_PAIR_SCORE        (2 << RANK_SHL)
#define TWO_KIND_SCORE        (1 << RANK_SHL)

#define ONE_PAIR_SCORE        (TWO_KIND_SCORE)

typedef uint8_t u8;
typedef int8_t s8;
typedef uint32_t u32;
typedef int32_t s32;

typedef struct { int32_t len; u8 entry[52]; } CardPileType;

static char *handstrs[16] = { "high card", "one pair", "two pair", "three of a kind", "straight", "flush", "full house", "four of a kind", "straight flush", "err", "err", "err", "err", "err", "err", "err" };
static char *kickerstrs[16] = { "", "kickers", "kicker", "kickers", "high", "high", "full of", "kicker", "high", "err", "err", "err", "err", "err", "err", "err" };

static u32 CardValue[52] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 
};

static u32 CardSuit[52] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
};

int32_t cardstr(char *cardstr,uint8_t card)
{
    int32_t suit; char *cardc = "A234567890JQK",suitc[4] = { 'C', 'D', 'H', 'S' };
    suit = card / 13;
    card %= 13;
    if ( card == 9 )
        sprintf(cardstr,"10%c",suitc[suit]);
    else sprintf(cardstr,"%c%c",cardc[card],suitc[suit]);
    return(card);
}

static u32 CardSuitIdx[52] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3
};

static u32 CardMask[52] = {
	1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
	1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
	1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
	1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000
};

static u32 FiveCardDrawScoreFast (u32 c0, u32 c1, u32 c2, u32 c3, u32 c4, u32 u)
{
    u32 y,z,m1,m2,m3,m4;
	// Test for single suitedness
	u = u & (u - 1);
	// Build masks of 1, 2, 3, and 4 of a kind.
	m1  = c0 | c1;
	m2  = c1 & c0;

	m2 |= c2 & m1;
	m1 |= c2;

	m2 |= c3 & m1;
	m1 |= c3;

	m2 |= c4 & m1;
	m1 |= c4;

	if (m2 == 0) {                   // No pairs?
		// Is the mask a sequence of 1 bits?
		z  = m1 & (m1 - 1);
		z ^= m1;
		y  = (z << 5) - z;
		// Deal with the bicycle/wheel 5,4,3,2,Ace straight
		if  (m1 == 0x100F) {
			if (u != 0) return STRAIGHT_SCORE + 0xF;
			return STRAIGHT_FLUSH_SCORE + 0xF;
		}
		if (y == m1) {
			if (u != 0) return STRAIGHT_SCORE + m1;
			return STRAIGHT_FLUSH_SCORE + m1;
		}
		if (u != 0) return m1;	// Nothing
		return FLUSH_SCORE + m1;
	}
	/*
	// m1 = c0 | ... | c4
	// m2 = (c0 & c1) | ((c0|c1) & c2) | ((c0|c1|c2) & c3) | ((c0|c1|c2|c3) & c4)
	// m3 = mask of 3 or 4 of a kind.
	// m4 = mask of 4 of a kind.
	*/
	m1  = c0 | c1;
	m2  = c1 & c0;

	m3  = c2 & m2;
	m2 |= c2 & m1;
	m1 |= c2;

	m4  = c3 & m3;
	m3 |= c3 & m2;
	m2 |= c3 & m1;
	m1 |= c3;

	m4 |= c4 & m3;
	m3 |= c4 & m2;
	m2 |= c4 & m1;
	m1 |= c4;

	m1 &= ~m2;
	if (m3 == 0) {
		if ((m2 & (m2 - 1)) == 0)
			return TWO_KIND_SCORE + (m2 << SUBR_SHL) + m1;
		return TWO_PAIR_SCORE + (m2 << SUBR_SHL) + m1;
	}
	m2 &= ~m3;
	if (m4 == 0) {
		if (m2 == 0)
			return THREE_KIND_SCORE + (m3 << SUBR_SHL) + m1;
		return FULL_HOUSE_SCORE + (m3 << SUBR_SHL) + m2;
	}
	return FOUR_KIND_SCORE + (m4 << SUBR_SHL) + m1;
}

static u32 FiveCardDrawScore (const u8 * h)
{
    u32 c0, c1, c2, c3, c4,u;
	// Make suits powers of two.
	u  = CardSuit[h[0]];
	u |= CardSuit[h[1]];
	u |= CardSuit[h[2]];
	u |= CardSuit[h[3]];
	u |= CardSuit[h[4]];
	// Make cards powers of two.
	c0 = CardMask[h[0]];
	c1 = CardMask[h[1]];
	c2 = CardMask[h[2]];
	c3 = CardMask[h[3]];
	c4 = CardMask[h[4]];
	return FiveCardDrawScoreFast (c0, c1, c2, c3, c4, u);
}

static u32 SevenCardDrawFlush (const u8 * h, const u32 c[7])
{
    static s32 LG2TAB[9] = {-1, 0, 1, -1, 2, -1, -1, -1, 3};
    u32 i,t,f[4]; s32 cc[4],s;
	// Make suits powers of two.
    // There is at most one flush in a 7 card hand.  So up to 4 masks arecreated, each being the set of cards in one particular suit.
    // As themasks are created a maximum countdown from 4 is tracked.
#if 0
	s = (((((u32 *) h)[1])) * 5) & 0x00C0C0C0;
	i = (((((u32 *) h)[0])) * 5) & 0xC0C0C0C0;
	s = ((s * (1 + 64 + 4096)) >> 8) & 0x3F00;
	i = ((i * (1 + 64 + 4096 + 262144)) >> 24) | s;
#endif

	f[0]  = f[1]  = f[2]  = f[3]  = 0;
	cc[0] = cc[1] = cc[2] = cc[3] = 4;

	i = CardSuitIdx[h[0]];
	f[i]  = c[0]; cc[i]--;

	i = CardSuitIdx[h[1]];
	f[i] |= c[1]; cc[i]--;

	i = CardSuitIdx[h[2]];
	f[i] |= c[2]; cc[i]--;

	i = CardSuitIdx[h[3]];
	f[i] |= c[3]; cc[i]--;

	i = CardSuitIdx[h[4]];
	f[i] |= c[4]; cc[i]--;

	i = CardSuitIdx[h[5]];
	f[i] |= c[5]; cc[i]--;

	i = CardSuitIdx[h[6]];
	f[i] |= c[6]; cc[i]--;

	// If any of the counts goes below 0, then that suit has at least 5 cards in it.

	if (((cc[0] | cc[1]) | (cc[2] | cc[3])) < 0) {

		// Map the negative count (of which there is at most 1) to the suit index.

		s = (((cc[0] & 8) | (cc[1] & 16)) | ((cc[2] & 32) | (cc[3] & 64))) >> 3;
		s = LG2TAB[s];

		// Work out the top 5 cards, so that the proper flush is also known ...

		t = f[s];
		while (cc[s] < -1) {
			t &= t - 1;			// Rip off last bit.
			cc[s]++;
		}

		// ... but also keep the low part so that all straight flushes can still be tested for.

		return f[s] | (t << SUBR_SHL);
	}
	// 0 -> indicates there is no flush in the hand.
	return 0;
}

#define SevenCardDrawFlushScore(f) (FLUSH_SCORE + ((f) >> SUBR_SHL))

u32 SevenCardDrawScore (const u8 * h)
{
    u32 c[7],f, t, s, u, v,m1, m2, m3, m4;
	c[0] = CardMask[h[0]];
	c[1] = CardMask[h[1]];
	c[2] = CardMask[h[2]];
	c[3] = CardMask[h[3]];
	c[4] = CardMask[h[4]];
	c[5] = CardMask[h[5]];
	c[6] = CardMask[h[6]];
	// Work out flush mask always, since its only redundant in the case of a full house or 4 of a kind.
	f = SevenCardDrawFlush (h, c);
	// t is the full card mask
	t = ((c[0] | c[1]) | (c[2] | c[3])) | (c[4] | c[5] | c[6]);
	// If 7 cards are found in a row ...
	s  = t & (t - 1);
	v  = s ^ t;
	u  = (v << 7) - 1;
	u &= ~(u >> 7);
	// ... then work out the possible straight flush/bicycle, straight, and flush possibilities.
	if ((u & t) == u) {
		if (f) {
			// Intersect the flush mask with the straight mask to try to figure out if we have a straight flush.
			s  = f & u;
			u  = s & (s - 1);
			u ^= s;
			u  = (u << 7) - 1;
			u &= ~(u >> 5);
			t  = u >> 1;
 			v  = u >> 2;
			if ((u & s) == u) return STRAIGHT_FLUSH_SCORE + u;
			if ((t & s) == t) return STRAIGHT_FLUSH_SCORE + t;
			if ((v & s) == v) return STRAIGHT_FLUSH_SCORE + v;
			// Deal with possible bicycle/wheel 5,4,3,2,Ace straight flush
			if ((0x100F & f) == 0x100F)
				return STRAIGHT_FLUSH_SCORE + 0xF;
			return SevenCardDrawFlushScore (f);
		}
		u &= ~(u >> 5);
		return STRAIGHT_SCORE + u;
	}
	// If at most 6 cards are found in a row ...
	u  = (v << 6) - 1;
	u &= ~(u >> 6);
	if ((u & t) != u) {
		u  = s & (s - 1);
		u ^= s;
		u  = (u << 6) - 1;
		u &= ~(u >> 6);
	}
	// ... then work out the possible straight flush/bicycle, straight, and flush possibilities.
	if ((u & t) == u) {
		if (f) {
			s  = f & u;
			u  = s & (s - 1);
			u ^= s;
			u  = (u << 6) - 1;
			u &= ~(u >> 5);
			t  = u >> 1;
			if ((u & s) == u) return STRAIGHT_FLUSH_SCORE + u;
			if ((t & s) == t) return STRAIGHT_FLUSH_SCORE + t;
			// Deal with possible bicycle/wheel 5,4,3,2,Ace straight flush
			if ((0x100F & f) == 0x100F)
				return STRAIGHT_FLUSH_SCORE + 0xF;
			return SevenCardDrawFlushScore (f);
		}
		u &= ~(u >> 5);
		return STRAIGHT_SCORE + u;
	}
	// If at most 5 cards are found in a row ...
	u  = (v << 5) - 1;
	u &= ~(u >> 5);
	if ((u & t) != u) {
		v  = s;
		s  = s & (s - 1);
		v ^= s;
		u  = (v << 5) - 1;
		u &= ~(u >> 5);
		if ((u & t) != u) {
			u  = s & (s - 1);
			s ^= u;
			u  = (s << 5) - 1;
			u &= ~(u >> 5);
		}
	}
	// ... then work out the possible straight flush/bicycle, straight, and flush possibilities.
	if ((u & t) == u) {
		if (f) {
			s  = f & u;
			u  = s & (s - 1);
			u ^= s;
			u  = (u << 5) - 1;
			u &= ~(u >> 5);
			if ((u & s) == u) {
				return STRAIGHT_FLUSH_SCORE + u;
			}
			// Deal with possible bicycle/wheel 5,4,3,2,Ace straight flush
			if ((0x100F & f) == 0x100F)
				return STRAIGHT_FLUSH_SCORE + 0xF;
			return SevenCardDrawFlushScore (f);
		}
		u &= ~(u >> 5);
		return STRAIGHT_SCORE + u;
	}
	// Deal with the bicycle/wheel 5,4,3,2,Ace straight
	if ((0x100F & t) == 0x100F) {
		if (f)
        {
			if ((0x100F & f) == 0x100F)
				return STRAIGHT_FLUSH_SCORE + 0xF;
			return SevenCardDrawFlushScore (f);
		}
		return STRAIGHT_SCORE + 0xF;
	}
	/*
	// m1 = c0 | ... | c4
	// m2 = (c0 & c1) | ((c0|c1) & c2) | ((c0|c1|c2) & c3) | ((c0|c1|c2|c3) & c4)
	// m3 = mask of 3 or 4 of a kind.
	// m4 = mask of 4 of a kind.
	*/

	m1  = c[0] | c[1];
	m2  = c[1] & c[0];

	m3  = c[2] & m2;
	m2 |= c[2] & m1;
	m1 |= c[2];

	m4  = c[3] & m3;
	m3 |= c[3] & m2;
	m2 |= c[3] & m1;
	m1 |= c[3];

	m4 |= c[4] & m3;
	m3 |= c[4] & m2;
	m2 |= c[4] & m1;
	m1 |= c[4];

	m4 |= c[5] & m3;
	m3 |= c[5] & m2;
	m2 |= c[5] & m1;
	m1 |= c[5];

	m4 |= c[6] & m3;
	m3 |= c[6] & m2;
	m2 |= c[6] & m1;
	m1 |= c[6];
	// Make sure the m1 is just the mask of singleton cards.
	m1 &= ~m2;
	// No 3 or 4 of a kinds.
	if (m3 == 0) {
		if (f) {
			return SevenCardDrawFlushScore (f);
		}
		if (m2) {
			s = m2 & (m2 - 1);
			if (s == 0) {
				t = m1 & (m1 - 1);
				t &= (t - 1);
				return TWO_KIND_SCORE + (m2 << SUBR_SHL) + t;
			}
			v = m1;
			t = s & (s - 1);
			if (t) {
				v |= m2 ^ s;
				m2 = s;
			} else {
				v &= (v - 1);
			}
			v &= (v - 1);
			return TWO_PAIR_SCORE + (m2 << SUBR_SHL) + v;
		}
		// Nothing -- just remove the two low cards.
		m1 &= (m1 - 1);
		m1 &= (m1 - 1);
		return m1;
	}
	// 4 of a kind.
	if (m4) {
		m1 |= (m2 & ~m4);
		while ((m2 = (m1 & (m1 - 1))) != 0) {
			m1 = m2;
		}
		return FOUR_KIND_SCORE + (m4 << SUBR_SHL) + m1;
	}
	// 3 of a kind, but no other pair in the hand
	if ((m2 & ~m3) == 0) {
		t = m3 & (m3 - 1);
		// Two 3 of a kinds => Full House
		if (t)
			return FULL_HOUSE_SCORE + (t << SUBR_SHL) + (m3 ^ t);
		if (f)
			return SevenCardDrawFlushScore (f);
		// Just remove the two low cards, and score this as 3 of a kind.
		m1 &= (m1 - 1);
		m1 &= (m1 - 1);
		return THREE_KIND_SCORE + (m3 << SUBR_SHL) + m1;
	}
	// 3 of a kind and a seperate 2 of a kind (full house.)
	m2 &= ~m3;
	t = m2 & (m2 - 1);
	// If there are two 2 pairs in the hand, then pick the higher pair
	if (!t) t = m2;
	return FULL_HOUSE_SCORE + (m3 << SUBR_SHL) + t;
}

// Just a brute force 7 card draw ranking by picking each of the possible two cards to be skipped, and finding the score which is highest amongst the 21 possible 5 card sub-hands.
u32 SevenCardDrawScoreSlow (const u8 * h) {
s32 i, j, k;
u32 r, m;
u8 h2[5];

	m = 0;
	for (i=0; i < 6; i++) {
		for (k=0; k < i; k++) {
			h2[k] = h[k];
		}
		for (j=i+1; j < 7; j++) {
			for (k=i+1; k < j; k++) {
				h2[k-1] = h[k];
			}
			for (k=j+1; k < 7; k++) {
				h2[k-2] = h[k];
			}
			r = FiveCardDrawScore (h2);
			if (r > m) m = r;
		}
	}
	return m;
}

// A correctly distributed (ignoring the problem of using "rand() % x") reshuffling of your cards.
static void Shuffle (CardPileType * c)
{
    int32_t i, j, k; u8 t;
	for (i = 0; i < (c->len - 1); i++)
    {
		k = (RAND_MAX / (c->len - i)) * (c->len - i);
		do {
			j = rand ();
		} while (j >= k);
		j = i + (j % (c->len - i));
		t = c->entry[i];
		c->entry[i] = c->entry[j];
		c->entry[j] = t;
	}
}

static int32_t Deal (CardPileType * h, CardPileType * d, int32_t n)
{
    int32_t i;
	for (i=0; i < n && d->len > 0; i++)
    {
		d->len--;
		h->entry[ h->len ] = d->entry[ d->len ];
		h->len++;
	}
	return i;
}

static void InitDeck (CardPileType * deck)
{
    u8 i;
	deck->len = 52;
	for (i=0; i < 52; i++) deck->entry[i] = i;
}

static void DisplayCard (u8 c, char out[])
{
    // char suitdisp[9] = { 0, 5, 4, 0, 3, 0, 0, 0, 6 };
    static char suitdisp[9] = { 0, 'c', 'd', 0, 'h', 0, 0, 0, 's' };
    char s[4];
	s[0] = "        1    "[CardValue[c]];
	s[1] = "234567890JQKA"[CardValue[c]];
	s[2] = suitdisp[CardSuit[c]];
	s[3] = '\0';
    strcat (out, " ");
    strcat (out, s);
}

void DisplayHand5 (const CardPileType * h) {
    char out[128];
    int i;
    
	out[0] = '\0';
	for (i=0; i < 5; i++) DisplayCard (h->entry[i], out);
	sprintf (out + strlen (out), " => %08X\n", (int)FiveCardDrawScore (&h->entry[0]));
	printf ("%s", out);
}

void set_cardstr(char *cardstr,uint32_t c)
{
    /*static char suitdisp[9] = { 0, 'c', 'd', 0, 'h', 0, 0, 0, 's' };
	cardstr[0] = "        1    "[CardValue[c % 13]];
	cardstr[1] = "234567890JQKA"[CardValue[c % 13]];
	cardstr[2] = suitdisp[CardSuit[c]];
	cardstr[3] = '\0';*/

     int32_t i,j=0;
    c >>= 1;
     for (i=12; i>=0; i--)
        if ( ((1 << i) & c) != 0 )
        {
            cardstr[j++] = "        1    "[i];
            cardstr[j++] = "234567890JQKA"[i];
            cardstr[j++] = ' ';
        }
    cardstr[j++] = 0;
}

uint32_t set_handstr(char *handstr,uint8_t cards[7],int32_t verbose)
{
    char cardstr[32],cardstr2[32],*kickerstr,*str; uint32_t score,i;
    handstr[0] = 0;
    if ( cards == 0 )
    {
        handstr[0] = 0;
        printf("set_handstr: null cards??\n");
        return(0);
    }
    for (i=0; i<7; i++)
        if ( cards[i] < 0 || cards[i] >= 52 )
        {
            //printf("illegal card[%d] %d\n",i,cards[i]);
            return(0);
        }
   	score = SevenCardDrawScore (&cards[0]);
    set_cardstr(cardstr,(score>>SUBR_SHL) & SUBR_SHLMASK);
    set_cardstr(cardstr2,score & SUBR_SHLMASK);
    kickerstr = kickerstrs[(score>>RANK_SHL)&15];
    str = handstrs[(score>>RANK_SHL)&15];
    if ( verbose != 0 )
    {
        if ( strcmp(kickerstr,"high") == 0 )
            sprintf(handstr,"%c%c high %s",cardstr2[0],cardstr2[1],str);
        else if ( strcmp(str,"full house") == 0 )
            sprintf(handstr,"%c%c full of %c%c",cardstr[0],cardstr[1],cardstr2[0],cardstr2[1]);
        else if ( strcmp(str,"three of a kind") == 0 )
            sprintf(handstr,"set of %c%c with kickers %c%c %c%c",cardstr[0],cardstr[1],cardstr2[0],cardstr2[1],cardstr2[3],cardstr2[4]);
        else if ( strcmp(str,"two pair") == 0 )
            sprintf(handstr,"two pair %c%c and %c%c with %c%c kicker",cardstr[0],cardstr[1],cardstr[3],cardstr[4],cardstr2[0],cardstr2[1]);
        else if ( strcmp(str,"one pair") == 0 )
            sprintf(handstr,"pair of %c%c with %c%c kicker",cardstr[0],cardstr[1],cardstr2[0],cardstr2[1]);
        else sprintf(handstr,"%s %s %s %s",str,cardstr,kickerstr,cardstr2);
    }
    else
    {
        if ( strcmp(kickerstr,"high") == 0 )
            sprintf(handstr,"%c%c high %s",cardstr2[0],cardstr2[1],str);
        else if ( strcmp(str,"full house") == 0 )
            sprintf(handstr,"fullhouse %c%c %c%c",cardstr[0],cardstr[1],cardstr2[0],cardstr2[1]);
        else if ( strcmp(str,"three of a kind") == 0 )
            sprintf(handstr,"trip %c%c",cardstr[0],cardstr[1]);
        else if ( strcmp(str,"two pair") == 0 )
            sprintf(handstr,"two pairs %c%c %c%c",cardstr[0],cardstr[1],cardstr[3],cardstr[4]);
        else if ( strcmp(str,"one pair") == 0 )
            sprintf(handstr,"pair %c%c",cardstr[0],cardstr[1]);
        else sprintf(handstr,"%s",cardstr2);
    }
    return(score);
}

void DisplayHand7(char *handstr,uint8_t *cards)
{
    uint32_t x,y; int32_t i; char out[512];
	out[0] = '\0';
	for (i=0; i<7; i++)
        DisplayCard (cards[i], out);
	x = SevenCardDrawScore (cards);
	y = SevenCardDrawScoreSlow (cards);
    set_handstr(handstr,cards,1);
	if ( x != y )
        fprintf(stderr,"Error slow score %08x vs fast score %08x???\n",y,x);
     sprintf (out + strlen (out), " => %08x %6d %6d ->   (%s)",x,(x>>SUBR_SHL)&SUBR_SHLMASK,x&SUBR_SHLMASK,handstr);
    printf("%s\n",out);
}

void poker_test()
{
    char *_mbstr(double n);
    CardPileType Deck,Hands[1000]; uint32_t c,starttime,score; uint64_t total,counter; char handstr[512]; uint8_t *cards;
    //srand (0);
	InitDeck (&Deck);
	Shuffle (&Deck);
	for (c=0; c<(sizeof(Hands)/sizeof(*Hands)); c++)
    {
		Deal (&Hands[c],&Deck,7);
		DisplayHand7(handstr,Hands[c].entry);
		Deal (&Deck,&Hands[c],7);
		Shuffle(&Deck);
	}
    starttime = (uint32_t)time(NULL);
#ifndef _WIN32
    while ( (uint32_t)time(NULL) == starttime )
        usleep(100);
    total = counter = 0;
    while ( (uint32_t)time(NULL) < starttime+11 )
    {
        for (c=0; c<1000; c++,counter++)
        {
            cards = Hands[c % (sizeof(Hands)/sizeof(*Hands))].entry;
            score = SevenCardDrawScore(cards);
            total += score;
        }
    }
    char *mbstr(char *str,double val);
    char str[65]; printf("counter.%llu %s in 10 seconds: ave score %llx\n",(long long)counter,mbstr(str,counter),(long long)(total/counter));
#endif
}
