/*In this code, I suppose Bob want to 
 *encrypt an simple text file then send
 *it to Alice.
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
typedef long long LL;

struct ECPoint {
	LL x;
	LL y;
};
struct domain_parameter {
	LL p;
	LL A;
	LL B;
	LL x;
	LL y;
	LL n;
	LL q;
};
struct ciphertext {
	struct ECPoint* C1;
	struct ECPoint* C2;
};
typedef struct domain_parameter DP;
typedef struct ECPoint point;
typedef struct ciphertext c_text;

point* doubleAndAdd(point*, LL, LL, LL);
LL power(LL, LL, LL);
LL inversionModP(LL, LL);
point* ECAdd(point*, point*, LL, LL);
LL squareRoot(LL, LL);//compute sqrt(a) in module p
point* keyCreation(DP, LL);
point* encode(DP, LL);
c_text* encryption(DP, point*, point*);
point* decryption(DP, c_text*, LL);
LL decode(DP, point*);

int main(int argc, char* argv[])
{
	if(argc != 3)
	{
		printf("Usage: <executable file> <input file> <output file>\n");
		return 0;
	}
	FILE* infp;
	FILE* outfp;
	char d;
	DP pa;
	LL decode_c;
	//This is domain parameter, you can change if you want
	pa.p = 9463;
	pa.A = 1027;
	pa.B = 6584;
	pa.x = 4878;
	pa.y = 4444;
	pa.n = 9549;
	pa.q = 20;
	//---------------------------------------------------
	srand(time(NULL));
	point* QA = (point*)malloc(sizeof(point));
	point* P = (point*)malloc(sizeof(point));
	point* Pm = (point*)malloc(sizeof(point));
	printf("Alice choose private key 12\n");
	QA = keyCreation(pa, 12);//Change Alice's private key here if you want
	printf("public key of Alice (%lli, %lli)\n", QA->x, QA->y);
	c_text* cipher = (c_text*)malloc(sizeof(c_text));
	infp = fopen(argv[1], "r");
	outfp = fopen(argv[2], "w");
	printf("cipher text: \n");
	while(!feof(infp))
	{
		d = 0;
		fscanf(infp, "%c", &d);
		if(d != 0)
		{
			P = encode(pa, (LL)d);
			cipher = encryption(pa, P, QA);
			printf("%lli%lli %lli%lli ", cipher->C1->x, cipher->C1->y, cipher->C2->x, cipher->C2->y);
			Pm = decryption(pa, cipher, 12);
			decode_c = decode(pa, Pm);
			fprintf(outfp, "%c", (char)decode_c);
		}
	}
	fclose(infp);
	fclose(outfp);
	free(QA);
	free(P);
	free(Pm);
	free(cipher);
	return 0;
}

LL inversionModP(LL p, LL a)
{
	LL u = a, v = p, A = 1, C = 0;
	while(u != 0)
	{
		while(u%2 == 0)
		{
			u = u / 2;
			if(A%2 == 0)
				A = A / 2;
			else
				A = (A + p) / 2;
		}
		while(v%2 ==0)
		{
			v = v / 2;
			if(C%2 == 0)
				C = C / 2;
			else
				C = (C + p) / 2;
		}
		if(u >= v)
		{
			u = u - v;
			A = A - C;
		}
		else
		{
			v = v - u;
			C = C - A;
		}
	}
	if(C < 0)
		C = C + p;
	return C;
}

LL power(LL a, LL b, LL p) // compute a^b
{
	LL i, temp = 1;
	for(i = 0;i < b;i++)
		temp = (temp * a)%p;
	return temp;
}

point* ECAdd(point* P, point* Q, LL A, LL p)
{
	point* R = (point*)malloc(sizeof(point));
	LL inverse;
	LL slope;
	if(P->x == 0 && P->y == 0)
		R = Q;
	else if(Q->x == 0 && Q->y == 0)
		R = P;
	else if(P->x == Q->x && P->y == Q->y)
	{
		inverse = inversionModP(p, (2*P->y)%p>=0?(2*P->y)%p:((2*P->y)%p)+p);
		slope = ((3*power(P->x, 2, p) + A) * inverse)%p;
		if(slope < 0)
			slope = slope + p;
		R->x = (LL)(power(slope, 2, p) - 2*P->x)%p;
		R->y = (LL)(slope*(P->x - R->x) - P->y)%p;
		if(R->x < 0)
			R->x = R->x + p;
		if(R->y < 0)
			R->y = R->y + p;
		
		return R;
	}
	else
	{
		
		inverse = inversionModP(p, (Q->x-P->x)<0?(Q->x-P->x+p):Q->x-P->x);
		slope = ((Q->y - P->y) * inverse)%p;
		if(slope < 0)
			slope = slope + p;
		R->x = (LL)(power(slope, 2, p) - P->x - Q->x)%p;
		R->y = (LL)(slope*(P->x - R->x) - P->y)%p;
		if(R->x < 0)
			R->x = R->x + p;
		if(R->y < 0)
			R->y = R->y + p;
		return R;
	}
}
//Tonelli-Shanks Algorithm
LL squareRoot(LL a, LL p)
{
	LL Q = p - 1, S = 0;
	while(Q%2 == 0)
	{
		Q >>= 1;
		S++;
	}
	if(S == 1)
		return power(a, (p+1)/4, p);
	LL z;
	while(1)
	{
		z = 1 + rand()%(p-1);
		if(power(z, (p-1)/2, p) != 1)
			break;
	}
	LL c = power(z, Q, p);
	LL R = power(a, (Q+1)/2, p);
	LL t = power(a, Q, p);
	LL M = S, b, i;
	while(1)
	{
		if(t%p == 1)
			break;
		for(i = 1;i < M;i++)
		{
			if(power(t, 1<<i, p) == 1)
				break;
		}
		b = power(c, 1<<(M-i-1), p);
		R = (R*b)%p;
		t = (t*b*b)%p;
		c = (b*b)%p;
		M = i;
	}
	return (R%p + p)%p;
}

point* doubleAndAdd(point* P, LL A, LL p, LL n)
{
	point* Q = (point*)malloc(sizeof(point));
	point* R = (point*)malloc(sizeof(point));
	Q->x = P->x;
	Q->y = P->y;
	R->x = 0;
	R->y = 0;
	while(n > 0)
	{
		if(n%2 == 1)
			R = ECAdd(R, Q, A, p);
		Q = ECAdd(Q, Q, A, p);
		n = n/2;
	}
	free(Q);
	return R;
}

point* keyCreation(DP pa, LL n)
{
	point* P = (point*)malloc(sizeof(point));
	point* G = (point*)malloc(sizeof(point));//Generator point
	G->x = pa.x;
	G->y = pa.y;
	P = doubleAndAdd(G, pa.A, pa.p, n);
	free(G);
	return P;
}

point* encode(DP pa, LL x)
{
	LL alpha, sigma; 
	point* P = (point*)malloc(sizeof(point));
	x = (x*pa.q + 1)%pa.p;
redo:
	alpha = power(x, 3, pa.p) + (pa.A*x)%pa.p + pa.B%pa.p;
	alpha = alpha%pa.p;
	sigma = power(alpha, (pa.p-1)/2, pa.p);
	if(sigma != 1)
	{
		x++;
		goto redo;
	}
	P->x = x;
	P->y = squareRoot(alpha, pa.p);
	return P;
}
// Q is other's public key
// P is point of plaintext after encoding
c_text* encryption(DP pa, point* P, point* Q)
{
	c_text* C = (c_text*)malloc(sizeof(c_text));
	point* G = (point*)malloc(sizeof(point));
	G->x = pa.x;
	G->y = pa.y;
	int r = 56;
	C->C1 = doubleAndAdd(G, pa.A, pa.p, r);
	C->C2 = doubleAndAdd(Q, pa.A, pa.p, r);
	C->C2 = ECAdd(C->C2, P, pa.A, pa.p);
	free(G);
	return C;
}
//k is private key
point* decryption(DP pa, c_text* cipher, LL k)
{
	point* M = (point*)malloc(sizeof(point));
	point* Pm = (point*)malloc(sizeof(point));
	M = doubleAndAdd(cipher->C1, pa.A, pa.p, k);
	M->y = -M->y+pa.p;
	Pm = ECAdd(cipher->C2, M, pa.A, pa.p);
	free(M);
	return Pm;
}

LL decode(DP pa, point* P)
{
	LL m;
	m = (LL)(P->x - 1)/pa.q;
	return m;
}
