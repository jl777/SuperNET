/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

/*
 requires *vals and *vars to be initialized
 external calls: OS_milliseconds(), get_jfp_features(), get_yval(), set_ocas_model(), update_ocas_preds(), ocasCL_glue()
 */
//#include <dispatch/dispatch.h>

typedef float svmtype;

// fadedreamz@gmail.com - added for successful compilation, however, for MSVC probably require a particular OpenCL SDK
// to work with it (e,g nvidia or amd SDK)
typedef struct fake_opencl_double { //use a struct for double2 typedefinition on all OS - ca333@protonmail.ch
	double x;
	double y;
}double2;

#define MAX_VECTORS (1440 * 365 * 5)
#define MAIN_MAXCORES 16
#define c_to_refc(c) (c)
#define refc_to_c(refc) (refc)

#define CONDITION(feature) (feature)
#define FEATURE_THRESHOLD 10.
#define HWMPERC_THRESHOLD 101
#define HWMPERC_THRESHOLD0 HWMPERC_THRESHOLD

#ifdef INSIDE_OPENCL
#pragma OPENCL EXTENSION cl_khr_fp64: enable
#define local_barrier() barrier(CLK_LOCAL_MEM_FENCE)
#define global_barrier() barrier(CLK_GLOBAL_MEM_FENCE)
#else
//double get_features(register struct ocas_ptrs *PTRS,register int c,register int weekind,register int numfeatures,register double *features,register double *model,register double *addptr,register struct baserel_info *BR,register double wt);
svmtype *get_jfp_features(register int selector,register int numfeatures,register int c,register int weekind);

#endif

#define OCAS_INFINITY (-log(0.0))
#define OCAS_NEGINFINITY (log(0.0))
#define OCAS_DECAY .1
#define OCAS_BIAS 1.
#define OCAS_INDEX(ROW,COL,NUM_ROWS) ((COL)*(NUM_ROWS)+(ROW))
#define QPSOLVER_MAXITER 1000000
#define QPSOLVER_MINITER (QPSOLVER_MAXITER * .1)
//#define NUM_CUDA_GROUPS 14
//#define NUM_BUNDLE_ANSWERS 64
//#define NUM_TOPCOEFFIS 558
//#define SMALLVAL .00000000000001
//#define NUM_PRIMARY_FEATURES 4096
#ifdef __APPLE__
#define MAX_OCAS_LHS 512
#else
#define MAX_OCAS_LHS 2000
#endif
#define MAX_OCAS_FEATURES (1024 * 1024)

struct ptrhdr { long allocsize; void *ptr; int devid; char str[64]; };

struct ocas_lhsbuffers
{
	double H[MAX_OCAS_LHS * MAX_OCAS_LHS];
	double alpha[MAX_OCAS_LHS],b[MAX_OCAS_LHS],diag_H[MAX_OCAS_LHS],A0[MAX_OCAS_LHS],d[MAX_OCAS_LHS];
	double full_A[];
};

struct ocas_CLtmpspace
{
	double2 hpfb[MAX_VECTORS];
	int poslist[MAX_VECTORS],neglist[MAX_VECTORS];
};

struct ocas_CLbuffers
{
	double output_pred[MAX_VECTORS],old_output[MAX_VECTORS];
	double W[MAX_OCAS_FEATURES+4],oldW[MAX_OCAS_FEATURES+4],new_a[MAX_OCAS_FEATURES+4];
};

struct ocas_vars
{
	struct ptrhdr pH[256];
	double Q_P[TRADEBOTS_NUMANSWERS],Q_D[TRADEBOTS_NUMANSWERS];
	double netcuts[TRADEBOTS_NUMANSWERS],perc[TRADEBOTS_NUMANSWERS],hwmperc[TRADEBOTS_NUMANSWERS],lastmetrics[TRADEBOTS_NUMANSWERS][2];
	double learningrates[TRADEBOTS_NUMANSWERS][2],maxiters[TRADEBOTS_NUMANSWERS],dot_prod_WoldW[TRADEBOTS_NUMANSWERS],cutsum[TRADEBOTS_NUMANSWERS];
	double sq_norm_oldW[TRADEBOTS_NUMANSWERS],oldW0[TRADEBOTS_NUMANSWERS],W0[TRADEBOTS_NUMANSWERS],sq_norm_W[TRADEBOTS_NUMANSWERS];
	double predabs[TRADEBOTS_NUMANSWERS],predsum[TRADEBOTS_NUMANSWERS],dist[TRADEBOTS_NUMANSWERS];
	double xi[TRADEBOTS_NUMANSWERS],pratio[TRADEBOTS_NUMANSWERS],errperc[TRADEBOTS_NUMANSWERS],hwmdist[TRADEBOTS_NUMANSWERS];
    double answerabsaves[TRADEBOTS_NUMANSWERS],answeraves[TRADEBOTS_NUMANSWERS];
	int answercounts,firstweekinds[TRADEBOTS_NUMANSWERS];
	int posA[TRADEBOTS_NUMANSWERS],negA[TRADEBOTS_NUMANSWERS];
	int numIt[TRADEBOTS_NUMANSWERS],numlhs[TRADEBOTS_NUMANSWERS],nNZAlpha[TRADEBOTS_NUMANSWERS],trn_err[TRADEBOTS_NUMANSWERS];
	int qp_exitflag[TRADEBOTS_NUMANSWERS],exitflag[TRADEBOTS_NUMANSWERS],len[TRADEBOTS_NUMANSWERS];
	int have_pendingmodel[TRADEBOTS_NUMANSWERS],cutlen[TRADEBOTS_NUMANSWERS],good[TRADEBOTS_NUMANSWERS],bad[TRADEBOTS_NUMANSWERS];
	int nohwm[TRADEBOTS_NUMANSWERS],numposcuts[TRADEBOTS_NUMANSWERS],numnegcuts[TRADEBOTS_NUMANSWERS];
	struct ocas_CLbuffers *CLspaces[TRADEBOTS_NUMANSWERS];
	struct ocas_lhsbuffers *lhs[TRADEBOTS_NUMANSWERS];
    int *weekinds[TRADEBOTS_NUMANSWERS];
    float *answers,**features;
	//unsigned long CLallocsize,tmpallocsize,tmpCLallocsize;
    double C,TolRel,TolAbs,MaxTime,QPBound,QPSolverTolAbs,QPSolverTolRel;
    double output_time,sort_time,add_time,w_time,qp_solver_time,ocas_time; // total time spent in svm_ocas_solver
	int selector,numthreads,starti,modelind,c,refc,maxlen,numfeatures,firstweekind,startweekind,endweekind,numptrs,maxlhs;
};

/////////////////////////// Most of runtime is in the add/dot functions
#ifdef INSIDE_OPENCL
typedef double svmtype;

// numCLthreads: NUM_CUDA_CORES, numgroups: (numdocs + NUM_CUDA_CORES-1)/NUM_CUDA_CORES
__kernel void dot_featuresCL(__local void *lp,__global double *preds,int numfeatures,__global double *W,double W0,__global svmtype *matrix,int numdocs)
{
	register int i,j,docid;
	register double sum;
	register __global svmtype *features;
	if ( (docid = (int)get_global_id(0)) < numdocs )
	{
		sum = 0.;
		features = &matrix[docid * numfeatures];
		for (i=0; i<numfeatures; i++)
		{
			j = ((i + docid) % numfeatures);	// interleave global memory accesses statistically without any system overhead
			sum += W[j] * CONDITION(features[j]);
		}
		preds[docid] = sum + W0;
	}
}

// numCLthreads: NUM_CUDA_CORES, numgroups: (numfeatures + NUM_CUDA_CORES-1)/NUM_CUDA_CORES
__kernel void add_featuresCL(__local void *lp,__global double *new_a,int numfeatures,__global unsigned int *new_cutCL,int cutlen,__global svmtype *matrix,int numdocs)
{
	register int i,j,docid,dir,globalid = (int)get_global_id(0);
	register double sum;
	register __global svmtype *features;
	if ( (j = globalid) < numfeatures )
	{
		sum = 0.;
		for (i=0; i<cutlen; i++)
		{
			docid = new_cutCL[(i + globalid) % cutlen];
			dir = (docid & 1);
			docid >>= 1;
			if ( docid < numdocs )
			{
				features = &matrix[docid * numfeatures];
				if ( dir == 0 )
					sum += CONDITION(features[j]);
				else sum -= CONDITION(features[j]);
			}
		}
		new_a[j] = sum;
	}
}

#else

void ocas_purge(struct ocas_vars *vars)
{
    int32_t i;
    free(vars->answers);
    for (i=0; i<vars->maxlen; i++)
        if ( vars->features[i] != 0 )
            free(vars->features[i]);
    free(vars->features);
    for (i=0; i<TRADEBOTS_NUMANSWERS; i++)
    {
        if ( vars->CLspaces[i] != 0 )
            myaligned_free(vars->CLspaces[i],sizeof(*vars->CLspaces[i]));
        if ( vars->lhs[i] != 0 )
            myaligned_free(vars->lhs[i],sizeof(*vars->lhs[i]) + vars->numfeatures*vars->maxlhs*sizeof(double));
        if ( vars->weekinds[i] != 0 )
            free(vars->weekinds[i]);
    }
    free(vars);
}

/*static inline double dot_expanded_features(register double *W,register int c,register int selector,register int numfeatures)
 {
 fatal("dot_expanded_features not implemented");
 return(0);
 }

 static inline void add_expanded_features(register double *W,register double y,register int c,register int selector,register int numfeatures)
 {
 fatal("add_expanded_features not implemented");
 }*/

static inline double calc_ocas_output(register struct ocas_vars *vars,register int selector,register int c,register int weekind,register int answerind,register double *W,register double W0,register int numfeatures)
{
	register svmtype *features;
	register double feature,y,sum = 0.;
	register int coeffi;
	if ( (y= vars->answers[(weekind-vars->starti)*TRADEBOTS_NUMANSWERS + answerind]) != 0.f )
	{
		if ( (features= vars->features[weekind-vars->starti]) != 0 )//get_jfp_features(vars->selector,numfeatures,c,weekind)) != 0 )
		{
#ifdef OCAS_USE_TOPCOEFFIS
			for (int i=0; i<NUM_TOPCOEFFIS; i++)
			{
				coeffi = _Topcoeffis[answerind][i];
#else
            for (coeffi=0; coeffi<numfeatures; coeffi++)
            {
#endif
                    feature = features[coeffi];
                    if ( isnan(feature) == 0 && fabs(feature) < FEATURE_THRESHOLD )
                        sum += CONDITION(feature) * W[coeffi];
            }
        }
            //else sum = dot_expanded_features(W,c,vars->selector,numfeatures);
        sum = y * (W0 + sum);
    }
    // printf("%f ",sum);
    return(sum);
}

static inline void add_ocas_output(register double y,register struct ocas_vars *vars,register int selector,register int c,register int weekind,register int answerind,register double *W,register double *new_a,register int numfeatures)
{
    register int coeffi;
    register svmtype *features,feature;
    if ( y != 0 )
    {
        if ( (features= vars->features[weekind-vars->starti]) != 0 )//get_jfp_features(vars->selector,numfeatures,c,weekind)) != 0 )
        {
            //features = get_jfp_features(vars->selector,numfeatures,c,weekind);
#ifdef OCAS_USE_TOPCOEFFIS
            int32_t i;
            for (i=0; i<NUM_TOPCOEFFIS; i++)
            {
                coeffi = _Topcoeffis[answerind][i];
#else
            for (coeffi=0; coeffi<numfeatures; coeffi++)
            {
#endif
                feature = features[coeffi];
                if ( isnan(feature) == 0 && fabs(feature) < FEATURE_THRESHOLD )
                    new_a[coeffi] += y * CONDITION(feature);
            }
        }
        //else add_expanded_features(new_a,y,c,vars->selector,numfeatures);
    }
}

static inline void STocas_calc_outputs(register struct ocas_vars *vars,register int c,register int answerind,register double *output,register double *old_output,register double *W,register double W0,register int numfeatures,register int *weekinds,register int numdocs)
{
    register int i,j;
    //vars->good[answerind] = vars->bad[answerind] = 0;
    //printf("start STocas_calc_outputs.(%p %s.A%d %p) %p %p %p\n",vars,CONTRACTS[c],answerind,weekinds,output,old_output,W);
    for (i=0; i<numdocs; i++)
    {
        //old_output[i] = output[i];
        output[i] = calc_ocas_output(vars,vars->selector,c,weekinds[i],answerind,W,W0,numfeatures);
        if ( 1 && isnan(output[i]) != 0 )
        {
            svmtype *features = vars->features[weekinds[i]-vars->starti];//get_jfp_features(vars->selector,numfeatures,c,weekinds[i]);
            if ( features != 0 )
            {
                for (j=0; j<numfeatures; j++)
                    if ( isnan(features[j]) != 0 )
                        printf("%d ",j);
                printf("nans | i.%d w%d output %19.16f\n",i,weekinds[i],output[i]);
            }
        }
        else if ( output[i] != 0. )
        {
            if ( 0 && vars->answers[(i-vars->starti)*TRADEBOTS_NUMANSWERS + answerind]*output[i] <= 0 )
            {
                if ( vars->answers[(i-vars->starti)*TRADEBOTS_NUMANSWERS + answerind] != 0.f )
                    printf("(%f %f) ",vars->answers[(i-vars->starti)*TRADEBOTS_NUMANSWERS + answerind],output[i]);
            }
            //printf("[%f %f] ",vars->answers[(i-vars->starti)*TRADEBOTS_NUMANSWERS + answerind],output[i]);
        }
    }
    //printf("finish STocas_calc_outputs\n");
}

static inline void STocas_add_newcuts(register struct ocas_vars *vars,register int answerind,register int numfeatures,register int *weekinds,register int *new_cut,register int numcuts,register double *W,register double *new_a)
{
    register int weekind,dir,i,c = vars->c;
    memset(new_a,0,sizeof(*new_a) * numfeatures);
    //printf("STocas_add_newcuts numcuts.%d numfeatures.%d\n",numcuts,numfeatures);
    for (i=0; i<numcuts; i++)
    {
        weekind = new_cut[i];
        dir = (weekind & 1);
        weekind >>= 1;
        add_ocas_output(dir==0?1:-1,vars,vars->selector,c,weekind,answerind,W,new_a,numfeatures);
    }
}
//////////////////////////// end of add/dot functions
static inline double _dbufave(register double *buf,register int len)
{
    register int i,n;
    register double sum;
    sum = 0.;
    n = 0;
    for (i=0; i<len; i++)
    {
        if ( fabs(buf[i]) > 0.0000000001 )
        {
            n++;
            sum += buf[i];
        }
    }
    if ( n != 0 )
        sum /= n;
    if ( fabs(sum) <= 0.0000000001 )
        sum = 0.;
    return(sum);
}

static inline void add_newcut_entry(register struct ocas_vars *vars,register int answerind,register int *new_cut,register int i,register int weekind,register double y)
{
    weekind <<= 1;
    if ( y > 0 ) vars->numposcuts[answerind]++;
    else if ( y < 0 ) vars->numnegcuts[answerind]++, weekind |= 1;
    new_cut[vars->cutlen[answerind]++] = weekind;
}

static inline double validate_ocas_model(register struct ocas_vars *vars,register int answerind,register double *output_pred,register double *old_output,register int *weekinds,register int numdocs,register double *W,register double W0,register int numfeatures,register int paranoid)
{
    register svmtype *features;
    register double y,pred,perc,answer=0.,feature;
    register int i,j,pos,neg,good,bad,oldcuts,training_errors,weekind,nonz=0,posA,negA;
    for (i=pos=neg=good=bad=oldcuts=training_errors=posA=negA=0; i<numdocs; i++)
    {
        weekind = (weekinds == 0) ? i : weekinds[i];
        if ( (y= vars->answers[(weekind-vars->starti)*TRADEBOTS_NUMANSWERS + answerind]) != 0. )
        {
            if ( y > 0 ) posA++;
            else if ( y < 0 ) negA++;
            if ( paranoid != 0 )
            {
                pred = 0.;
                if ( (features= vars->features[weekind-vars->starti]) != 0 )//get_jfp_features(vars->selector,numfeatures,vars->c,weekind)) != 0 )
                {
                    for (j=nonz=0; j<numfeatures; j++)
                    {
                        if ( (feature= features[j]) != 0 )
                        {
                            if ( isnan(feature) == 0 && fabs(feature) < FEATURE_THRESHOLD )
                            {
                                nonz++;
                                pred += W[j] * CONDITION(feature);
                            }
                        }
                    }
                    if ( fabs(pred) > SMALLVAL )
                        pred += W0;
                }
                else pred = 0;//dot_expanded_features(W,c,selector,numfeatures);
                if ( output_pred[i] != 0 && fabs(pred - output_pred[i]) > .000001 )
                    //	if ( (rand() % 10000) == 0 )
                    printf("i.%d A %9.6f pred %9.6f != output_pred %9.6f [%14.10f]\n",i,answer,pred,output_pred[i],pred-output_pred[i]);
            }
            else pred = output_pred[i], nonz = numfeatures;
            if ( nonz != 0 )
            {
                if ( pred > 0 ) pos++;
                else if ( pred < 0 ) neg++;
                if ( pred*y > 0 ) good++;
                else if ( pred*y < 0 ) bad++;
            }
            if ( old_output[i] <= 1. )
            {
                oldcuts++;
                if ( old_output[i] <= 0. )
                    training_errors++;
            }
        }
    }
    nonz = 0;
    for (i=0; i<numfeatures; i++)
        if ( W[i] != 0. )
            nonz++;
    perc = (100.*(double)good) / MAX(1,(good+bad));
    printf(">>>>>> %d.A%02d.(+%-6d -%-6d oc.%-6d | good.%-6d bad.%-6d >>>>> %6.2f%% <<<<<).%-6d | W0 %9.6f W[%d] %9.6f | A +%-6d -%-6d | paranoid.%d numdocs.%d\n",c_to_refc(vars->c),answerind,pos,neg,oldcuts,good,bad,perc,training_errors,W0,nonz,_dbufave(W,numfeatures),posA,negA,paranoid,numdocs);
    return(perc);
}

static int _increasing_double(const void *a,const void *b)
{
#define double_a (*(double *)a)
#define double_b (*(double *)b)
    if ( double_b > double_a )
        return(-1);
    else if ( double_b < double_a )
        return(1);
    return(0);
#undef double_a
#undef double_b
}

static inline void calc_ocas_strategy(register struct ocas_vars *vars,register int answerind,register double C,register int numfeatures,register int len,register int *weekinds,register int *new_cut,register double *W,register double *oldW,register double *output,register double *old_output,register double2 *hpfb)
{
    double answermag;
    register int i,j,num_hp,good,bad,zero;
    register double Bval,Cval,newoutput,W0,oldW0,sq_norm_W,A0val,B0,dist,GradVal,t,t1,t2,t_new,val,GradVal_new,y,starttime,*preds = output;
    num_hp = 0;
    W0 = vars->W0[answerind]; oldW0 = vars->oldW0[answerind];
    A0val = vars->sq_norm_W[answerind] - (2. * vars->dot_prod_WoldW[answerind]) + vars->sq_norm_oldW[answerind];
    B0 = (vars->dot_prod_WoldW[answerind] - vars->sq_norm_oldW[answerind]);
    GradVal = B0;
    for (i=0; i<len; i++)
    {
        if ( (y= vars->answers[(weekinds[i]-vars->starti)*TRADEBOTS_NUMANSWERS + answerind]) != 0.f )
        {
            svmtype *features = vars->features[weekinds[i]-vars->starti];//get_jfp_features(vars->selector,numfeatures,vars->c,weekinds[i]);
            //printf("i.%d weekind.%d starti.%d y %f %p\n",i,weekinds[i],vars->starti,y,features);
            if ( 0 && features != 0 )
            {
                double oldsum=oldW0,sum=W0;
                for (j=0; j<numfeatures; j++)
                {
                    oldsum += oldW[j] * CONDITION(features[j]);
                    //sum += W[j] * CONDITION(features[j]);
                }
                //old_output[i] = oldsum*y;
                if ( 0 && fabs(sum*y - output[i]) > .000001 )
                {
                    printf("A%d numIt.%d docid.%-6d sum %11.7f * y%2.0f %11.7f != %11.7f output [%11.7f] W0 %11.7f oldW0 %11.7f\n",answerind,vars->numIt[answerind],i,sum,y,sum*y,output[i],output[i]-sum*y,W0,oldW0);
                    //output[i] = sum*y;
                }
                if ( fabs(oldsum*y - old_output[i]) > .000001 )
                {
                    if ( old_output[i] != 0 && oldW0 != 0 && (rand() % 1000) == 0 )
                        printf("A%d numIt.%d docid.%-6d oldsum %11.7f * y%2.0f %11.7f != %11.7f oldoutput [%11.7f] W0 %11.7f oldW0 %11.7f\n",answerind,vars->numIt[answerind],i,oldsum,y,oldsum*y,old_output[i],old_output[i]-oldsum*y,W0,oldW0);
                    old_output[i] = oldsum*y;
                }
            }
            Cval = C * (1. - old_output[i]);
            Bval = C * (old_output[i] - output[i]);
            if ( Bval != 0 )
                val = -(Cval / Bval);
            else val = OCAS_NEG_INF;
            if ( val > 0 )
            {
                hpfb[num_hp].y = Bval;
                hpfb[num_hp].x = val;
                num_hp++;
            }
            if ( (Bval < 0 && val > 0) || (Bval > 0 && val <= 0) )
                GradVal += Bval;
        }
    }
    //printf("num_hp.%d\n",num_hp);
    t = 0;
    if ( GradVal < 0 )
    {
        starttime = OS_milliseconds();
        qsort(hpfb,num_hp,sizeof(double2),_increasing_double);
        //ocas_sort(hpfb,num_hp);
        i = 0;
        while ( GradVal < 0 && i < num_hp )
        {
            t_new = hpfb[i].x;
            GradVal_new = GradVal + fabs(hpfb[i].y) + A0val*(t_new - t);
            if ( GradVal_new >= 0 )
                t = t + GradVal * (t - t_new) / (GradVal_new - GradVal);
            else t = t_new, i++;
            GradVal = GradVal_new;
        }
        vars->sort_time += OS_milliseconds() - starttime;
    }
    t = MAX(t,0.);					// just sanity check; t < 0 should not occur
    t1 = t;							// new (best so far) W
    t2 = t + OCAS_DECAY*(1. - t);	// new cutting plane
    W0 = oldW0 * (1. - t) + (t * W0);
    sq_norm_W = W0 * W0;
    for (j=0; j<numfeatures; j++)
    {
        W[j] = (oldW[j] * (1. - t)) + (t * W[j]);
        sq_norm_W += W[j] * W[j];
    }
    vars->W0[answerind] = W0;	vars->sq_norm_W[answerind] = sq_norm_W;
    vars->trn_err[answerind] = 0; dist = 0.;
    for (i=good=bad=zero=0; i<len; i++)	// select a new cut
    {
        if ( (y= vars->answers[(weekinds[i]-vars->starti)*TRADEBOTS_NUMANSWERS + answerind]) != 0.f )
        {
            answermag = fabs(y);	// 1.;
            if ( (old_output[i] * (1. - t2) + t2*output[i]) <= answermag ) //1.
                add_newcut_entry(vars,answerind,new_cut,i,weekinds[i],y);
            newoutput = (old_output[i] * (1. - t1)) + (t1 * output[i]);
            if ( 0 )	// won't match unless old_output corresponds with features*oldW
            {
                double sum=W0;
                svmtype *features = vars->features[weekinds[i]-vars->starti];//get_jfp_features(vars->selector,numfeatures,vars->c,weekinds[i]);
                if ( features != 0 )
                {
                    for (j=0; j<numfeatures; j++)
                        sum += W[j] * CONDITION(features[j]);
                    if ( fabs(sum*y - newoutput) > .0000001 )
                        printf("numIt.%d docid.%-6d w%-6d sum %11.7f * y%2.0f %11.7f != %11.7f newoutput [%11.7f] W0 %11.7f oldW0 %11.7f\n",vars->numIt[answerind],i,weekinds[i],sum,y,sum*y,newoutput,newoutput-sum*y,W0,oldW0);
                    newoutput = sum*y;
                }
            }
            if ( newoutput <= answermag )
            {
                vars->xi[answerind] += (answermag - newoutput);
                if ( newoutput <= 0. )
                    vars->trn_err[answerind]++;
            }
            preds[i] = y * newoutput;
            dist += fabs(preds[i] - y);
            old_output[i] = newoutput;
            if ( newoutput > 0. ) good++;
            else if ( newoutput < 0. )
            {
                bad++;
                //printf("(%f %f) ",y,newoutput);
            }
        } else zero++;//,printf("i.%d -> w%d | zeroes.%d good.%d bad.%d of len.%d\n",i,weekinds[i],zero,good,bad,len);
    }
    //printf("finished strategy\n");
    vars->good[answerind] = good; vars->bad[answerind] = bad; vars->dist[answerind] = dist / MAX(1,good+bad);
    vars->perc[answerind] = (100. * (double)vars->good[answerind]) / MAX(1,good+bad);
    if ( vars->perc[answerind] > vars->hwmperc[answerind] || (vars->perc[answerind] == vars->hwmperc[answerind] && (vars->hwmdist[answerind] == 0 || vars->dist[answerind] < vars->hwmdist[answerind])) )
    {
        double set_ocas_model(int refc,int answerind,double *W,double W0,int numfeatures,int firstweekind,int len,int bad,double dist,double predabs,int posA,int negA,double answerabs,double aveanswer);
        vars->W0[answerind] = set_ocas_model(vars->refc,answerind,vars->CLspaces[answerind]->W,vars->W0[answerind],vars->numfeatures,vars->firstweekind,vars->len[answerind],vars->trn_err[answerind],vars->dist[answerind],vars->predabs[answerind],vars->posA[answerind],vars->negA[answerind],vars->answerabsaves[answerind],0.);
        vars->nohwm[answerind] = 0;
        vars->hwmperc[answerind] = vars->perc[answerind]; vars->hwmdist[answerind] = vars->dist[answerind];
    }
    else vars->nohwm[answerind]++;
    //printf("good.%d bad.%d zero.%d errors.%d | selector.%d\n",good,bad,zero,vars->trn_err[answerind],vars->selector);
}

static inline double ocas_splx_solver(register int *nonzalphap,register int maxlhs,register double *d,register double *activeH,register double *diag_H,register double *f,register double C,register double *alpha,register int n,register int MaxIter,register double TolAbs,register double TolRel,register double QP_TH)
{
    register double *col_u=0,*col_v=0;
    register double QP,QD,lastQD,tmp,diff,distA,distB,etaA,etaB,improv,tmp_num,delta,x_neq0,xval,dval,diagval=0.,tmp_den,tau=0.;
    register int u=0,v=0,i,j,iter,nonzalpha=0,unlikely = 0;
    QP = distA = distB = OCAS_PLUS_INF;	lastQD = QD = OCAS_NEG_INF;
    x_neq0 = C;
    etaA = etaB = 0.;
    for (i=0; i<n; i++)
    {
        x_neq0 -= alpha[i];
        d[i] += f[i];
        if ( alpha[i] > 0. )
        {
            col_u = &activeH[maxlhs * i];
            for (j=0; j<n; j++)
                d[j] += col_u[j] * alpha[i];
        }
    }
    for (iter=0; iter<MaxIter; iter++)
    {
        // Compute primal and dual objectives
        for (tmp=OCAS_PLUS_INF,i=nonzalpha=0,QP=QD=delta=0; i<n; i++)
        {
            if ( alpha[i] != 0. )
            {
                nonzalpha++;
                QP += alpha[i] * (f[i] + d[i]);
                QD += alpha[i] * (f[i] - d[i]);
                delta += alpha[i] * d[i];
            }
            if ( d[i] < tmp )
                tmp = d[i], u = i;
        }
        QP *= .5; QD = QD*.5 + C * MIN(tmp,0.);
        if ( 0 && lastQD != 0. && lastQD != QD )
        {
            diff = (QD - lastQD);
            etaA = (distA != 0.) ? fabs(distA/diff) : 0.;
            etaB = (distB != 0.) ? fabs(distB/diff) : 0.;
            if ( etaA > 10*(MaxIter-iter) && etaB > 10*(MaxIter-iter) )
                unlikely++;
            else unlikely = 0;
        } else unlikely = 0;
        diff = (QP - QD);
        if ( 0 && (diff <= fabs(QP)*TolRel || diff <= TolAbs || QP <= QP_TH || unlikely > 100) )
        {
            if ( 0 )
            {
                if ( diff <= fabs(QP)*TolRel )
                    printf("caseA %f | ",diff - fabs(QP)*TolRel);
                else if ( diff <= TolAbs )
                    printf("caseB %f | ",diff - TolAbs);
                else if ( etaA > 2*(MaxIter-iter) && etaB > 2*(MaxIter-iter) )
                    printf("caseC etas %f %f | ",etaA,etaB);
                printf("%d: QP %f QD %f diff %f n.%d d0 %9.6f dA %9.6f %9.6f dB %9.6f %9.6f\n",iter,QP,QD,QP-QD,n,d[0],distA,etaA,distB,etaB);
            }
            break;
        }
        distA = (diff - fabs(QP)*TolRel);
        distB = (diff - TolAbs);
        lastQD = QD;
        if ( d[u] > 0 )
            u = -1;
        else delta -= C * d[u];
        // if satisfied then k-th block of variables needs update
        if ( delta > TolAbs && delta > (TolRel * fabs(QP)) )
        {
            // for fixed u select v = argmax_{i in I_k} Improvement(i)
            improv = OCAS_NEG_INF;
            for (i=0; i<=n; i++)
            {
                if ( i == u || (xval = ((i<n) ? alpha[i] : x_neq0)) <= 0. )
                    continue;
                if ( u != -1 )
                {
                    col_u = &activeH[maxlhs * u];
                    if ( i < n )
                        dval = (d[u] - d[u]), diagval = (diag_H[u] - 2.*col_u[i] + diagval);
                    else diagval = diag_H[u], dval = -d[u];
                }
                else if ( i < n )
                    dval = d[i], diagval = diag_H[i];
                else continue;
                if ( (tmp_den= xval * xval * diagval) > 0 )
                {
                    tmp_num = xval * dval;
                    if ( tmp_num < tmp_den )
                        tmp = tmp_num*tmp_num / tmp_den;
                    else tmp = tmp_num - .5 * tmp_den;
                    if ( 0 && i < n )	// jimbo tweak
                    {
                        tmp = alpha[i] * MIN(1.,tmp_num/tmp_den);
                        alpha[i] -= tmp;
                        if ( u == -1 )
                            x_neq0 += tmp;
                        else alpha[u] += tmp;
                    }
                    if ( tmp > improv )
                    {
                        improv = tmp;
                        tau = MIN(1.,tmp_num/tmp_den);
                        v = i;
                    }
                }
            }
            // update d = H*x + f
            if ( v < n )
            {
                tau *= alpha[v];
                alpha[v] -= tau;
                if ( u != -1 )
                {
                    alpha[u] += tau;
                    col_v = &activeH[maxlhs * v];
                    for (i=0; i<n; i++)
                        d[i] += tau * (col_u[i] - col_v[i]);
                }
                else
                {
                    x_neq0 += tau;
                    col_v = &activeH[maxlhs * v];
                    for (i=0; i<n; i++)
                        d[i] -= tau * col_v[i];
                }
            }
            else
            {
                tau *= x_neq0;
                alpha[u] += tau;
                x_neq0 -= tau;
                for (i=0; i<n; i++)
                    d[i] += tau * col_u[i];
            }
            QP -= improv;	// update objective value
        }
    }
    *nonzalphap = nonzalpha;
    return(-QP);
}

static inline void update_ocas_model(register double *W,register double *oldW,register struct ocas_vars *vars,register int numfeatures,register int answerind,register struct ocas_lhsbuffers *lhs,register int numlhs)
{
    register int i,j;
    register double alpha,sq_norm_W,dot_prod_WoldW,W0,oldW0;
    vars->sq_norm_oldW[answerind] = vars->sq_norm_W[answerind];
    oldW0 = vars->oldW0[answerind] = vars->W0[answerind];
    W0 = 0.;
    for (i=0; i<numlhs; i++)
    {
        if ( (alpha= lhs->alpha[i]) > 0 )
        {
            //printf("%9.6f ",alpha);
            for (j=0; j<numfeatures; j++)
                W[j] += alpha * lhs->full_A[OCAS_INDEX(j,i,numfeatures)];
            W0 += lhs->A0[i] * alpha;
        }
    }
    vars->W0[answerind] = W0;
    sq_norm_W = W0 * W0;
    dot_prod_WoldW = W0 * oldW0;
    for (j=0; j<numfeatures; j++)
    {
        //if ( W[j] != 0 )
        //	printf("W.%f ",W[j]);
        sq_norm_W += W[j] * W[j];
        dot_prod_WoldW += W[j] * oldW[j];
    }
    //printf("alphas %9.6f | W0 %f sw_norm_W %f | A%02d\n",_dbufave(lhs->alpha,numlhs),W0,sq_norm_W,answerind);
    vars->dot_prod_WoldW[answerind] = dot_prod_WoldW;
    vars->sq_norm_W[answerind] = sq_norm_W;
}

static inline void ocas_update_Lspace(register struct ocas_vars *vars,register int answerind,register double netcuts,register double cut_length,register int numfeatures,register double C,register double QPSolverTolAbs,register double QPSolverTolRel)
{
    register struct ocas_CLbuffers *ptr = vars->CLspaces[answerind];
    register struct ocas_lhsbuffers *lhs = vars->lhs[answerind];
    register double *new_col_H;
    register double sq_norm_a,maxiters,metric,tmp;
    register int i,j,iters,numlhs,maxlhs = vars->maxlhs;
    numlhs = vars->numlhs[answerind];
    new_col_H = &lhs->H[OCAS_INDEX(0,numlhs,maxlhs)];
    lhs->A0[numlhs] = netcuts;
    lhs->b[numlhs] = -cut_length;
    sq_norm_a = lhs->A0[numlhs] * lhs->A0[numlhs];
    for (j=0; j<numfeatures; j++)
    {
        lhs->full_A[OCAS_INDEX(j,numlhs,numfeatures)] = ptr->new_a[j];
        if ( fabs(ptr->new_a[j]) > 1000 )
        {
            //printf("(%d %9.6f %f) ",j,ptr->new_a[j],sq_norm_a);
            ptr->new_a[j] = 0.;
        }
        else
            sq_norm_a += ptr->new_a[j] * ptr->new_a[j];
        ptr->oldW[j] = ptr->W[j]; ptr->W[j] = 0.;
    }
    new_col_H[numlhs] = sq_norm_a;
    //printf("QPsolver.A%02d: ABS %f Rel %.11f numlhs.%d cutlen.%f netcuts.%f sq_norm_a %f netcuts.%f\n",answerind,QPSolverTolAbs,QPSolverTolRel,vars->numlhs[answerind],cut_length,lhs->A0[numlhs],sq_norm_a,netcuts);
    for (i=0; i<numlhs; i++)
    {
        tmp = lhs->A0[numlhs] * lhs->A0[i];
        for (j=0; j<numfeatures; j++)
            tmp += ptr->new_a[j] * lhs->full_A[OCAS_INDEX(j,i,numfeatures)];
        new_col_H[i] = tmp;
    }
    lhs->d[numlhs] = lhs->alpha[numlhs] = 0.;
    lhs->diag_H[numlhs] = lhs->H[OCAS_INDEX(numlhs,numlhs,maxlhs)];
    for (i=0; i <numlhs; i++)
        lhs->H[OCAS_INDEX(numlhs,i,maxlhs)] = lhs->H[OCAS_INDEX(i,numlhs,maxlhs)];
    numlhs = ++vars->numlhs[answerind];
    iters = vars->numIt[answerind];
    if ( vars->nohwm[answerind] > 3 )
        vars->maxiters[answerind] *= 1 + sqrt(vars->nohwm[answerind])/100;
    else if ( vars->nohwm[answerind] == 0 )
        vars->maxiters[answerind] *= .5;
    if ( vars->maxiters[answerind] > QPSOLVER_MAXITER )
        vars->maxiters[answerind] = QPSOLVER_MAXITER;
    if ( vars->maxiters[answerind] < QPSOLVER_MINITER )
        vars->maxiters[answerind] = QPSOLVER_MINITER;
    maxiters = MAX(QPSOLVER_MINITER,vars->maxiters[answerind]);
    vars->Q_D[answerind] = ocas_splx_solver(&vars->nNZAlpha[answerind],maxlhs,lhs->d,lhs->H,lhs->diag_H,lhs->b,C,lhs->alpha,vars->numlhs[answerind],MIN(maxiters,QPSOLVER_MAXITER),QPSolverTolAbs,QPSolverTolRel,OCAS_NEG_INF);
    metric = ((double)vars->len[answerind] / MAX(1,vars->trn_err[answerind])) / 1.;
    vars->lastmetrics[answerind][iters & 1] = metric;
    update_ocas_model(ptr->W,ptr->oldW,vars,numfeatures,answerind,lhs,numlhs);
}

static inline void start_ocas_iter(register struct ocas_vars *vars,register int c,register int answerind)
{
    if ( vars->pratio[answerind] == 0. )
        vars->pratio[answerind] = vars->answerabsaves[answerind];
    vars->good[answerind] = -1;
    vars->bad[answerind] = vars->trn_err[answerind] = vars->cutlen[answerind] = vars->numposcuts[answerind] = vars->numnegcuts[answerind] = 0;
    vars->xi[answerind] = vars->predsum[answerind] = vars->dist[answerind] = vars->cutsum[answerind] = vars->netcuts[answerind] = 0.;
}

static void ocas_print(struct ocas_vars *vars,int answerind,int ishwm,double C)
{
    int i;
    double dispvals[4];
    //printf("ocas_print.A%d\n",answerind);
    //printf("%s.A%02d %4d %8.2f | QP %9.3f QD %9.3f [%9.4f %7.3f] SV.%d %4d | M%9.6f (%9.6f max %8.1f %9.6f) %s.A%02d %9.6f%%\n",
    dispvals[0] = vars->Q_P[answerind]/1000000000.; dispvals[1] = (C * vars->Q_D[answerind])/1000000000.;
    dispvals[2] = (vars->Q_P[answerind]-C * vars->Q_D[answerind]) / 1000000000;
    dispvals[3] = (vars->Q_P[answerind]-C * vars->Q_D[answerind]) / MAX(1,fabs(vars->Q_P[answerind]));
    printf("%3d %d.A%02d +%d -%d",vars->nohwm[answerind],vars->refc,answerind,vars->good[answerind],vars->bad[answerind]);
    printf(" %4d %8.2f |QP %9.3f QD %10.2f [%11.2f %9.1f] SV.%3d %3d |M%9.3f errs.%-6d %-8.0f %5.2f%% errs %6.5f A%9.6f W0%9.6f D%11.9f\n",//[%7.4f%%]\n",
           vars->numIt[answerind],vars->ocas_time/1000,dispvals[0],dispvals[1],dispvals[2],dispvals[3],
           vars->nNZAlpha[answerind], vars->numlhs[answerind],
           // PTRS->lastmetrics[answerind],PTRS->learningrates[answerind][0],PTRS->maxiters[answerind],PTRS->learningrates[answerind][1],
           vars->lastmetrics[answerind][0],vars->trn_err[answerind],vars->maxiters[answerind],vars->perc[answerind],
           vars->errperc[answerind]/100,_dbufave(vars->CLspaces[answerind]->new_a,vars->numfeatures),vars->W0[answerind],
           vars->dist[answerind]/vars->answerabsaves[answerind]);//_dbufave(vars->hwmperc,81));//,vars->errperc+vars->perc);
    for (i=0; i<4; i++)
        if ( isnan(dispvals[i]) != 0 )
            break;
    if ( vars->lastmetrics[answerind][0] > 10 )
        usleep(vars->lastmetrics[answerind][0] * vars->lastmetrics[answerind][0]);
    /*if ( 0 && i < 4 )//|| (vars->answerind >= 32 && fabs(vars->W0) > .9) )
     {
     int save_model(int refc,int answerind,double *W,int numfeatures,double W0,double perc,int posA,int negA);
     memset(&vars->CLspaces[answerind],0,sizeof(vars->CLspaces[answerind]));
     vars->W0[answerind] = vars->oldW0[answerind] = 0.;
     vars->numIt[answerind] = 0;
     vars->perc[answerind] = vars->hwmperc[answerind] = 0.;
     printf("reset model %s.A%02d\n",CONTRACTS[vars->selector!=3?vars->refc:NUM_COMBINED],answerind);
     save_model(vars->refc,answerind,vars->CLspaces[answerind]->W,vars->numfeatures,vars->W0[answerind],vars->perc[answerind]);
     }*/
}

static inline void finish_ocasiter(register int answerind,register struct ocas_vars *vars,register double C)
{
    register double den;
    vars->have_pendingmodel[answerind] = 0;
    if ( vars->good[answerind] == 0 && vars->bad[answerind] == 0 )
    {
        vars->bad[answerind] = vars->trn_err[answerind];
        vars->good[answerind] = (vars->len[answerind] - vars->trn_err[answerind]);
    }
    den = MAX(1.,vars->good[answerind]+vars->bad[answerind]);
    if ( (vars->predabs[answerind] = (vars->predsum[answerind] / den)) != 0. )
        vars->pratio[answerind] = (vars->answerabsaves[answerind] / vars->predabs[answerind]);
    else vars->pratio[answerind] = 0.;
    vars->dist[answerind] = sqrt(vars->dist[answerind] / den);
    //printf("W0 %9.6f pred sum %f %f | pratio %f distsum %f (%f vs hwm %f)\n",vars->W0[answerind],vars->predsum[answerind],vars->predabs[answerind],vars->pratio[answerind],vars->dist[answerind],vars->perc[answerind],vars->hwmperc[answerind]);
    vars->errperc[answerind] = (100 * (double)vars->trn_err[answerind])/(double)MAX(1,vars->len[answerind]);
    vars->Q_P[answerind] = 0.5*vars->sq_norm_W[answerind] + (C * vars->xi[answerind]);
    vars->ocas_time = (vars->output_time + vars->w_time + vars->add_time + vars->sort_time + vars->qp_solver_time);
    ocas_print(vars,answerind,0,C);
}

static inline int ocas_iter(struct ocas_vars *vars,int max_nohwm)
{
    int Method = 1;
    int min_nohwm = 1;
    int skipflags[84];
    static int new_cut[MAX_VECTORS];
    static double2 hpfb[MAX_VECTORS];
    int inactives[81];
    register struct ocas_CLbuffers *ptr;
    register double netcuts,startmilli,y,psum,pcount,nosum;
    register int i,numfeatures,cutlen,lastanswerind,lwm=(1<<20),numactive,numthreads,answerind,*weekinds;
    numactive = 0;
    if ( (numfeatures= vars->numfeatures) > MAX_OCAS_FEATURES )
    {
        printf("numfeatures > MAX_OCAS_FEATURES\n");
        exit(-1);
    }
    psum = pcount = nosum = 0;
    {
        //printf("c.%d mask %lx %p\n",c,contractmask,PTRS->ocas[c]);
        memset(inactives,0,sizeof(inactives));
        lastanswerind = TRADEBOTS_NUMANSWERS;
        numfeatures = vars->numfeatures;
        answerind = 0;
        //printf("numIt.%d ocas iter.%s A.mask%lx len.%d CLspace.%p lhs.%p | vars.%p\n",vars->numIt[answerind],CONTRACTS[c_to_refc(c)],answerindmask,vars->len[answerind],vars->CLspaces[answerind],vars->lhs[answerind],vars);
        memset(skipflags,0,sizeof(skipflags));
        for (answerind=0; answerind<lastanswerind; answerind++)
        {
            //printf("answerind.%d of %d %ld, active CLspace.%p weekinds.%p | nohwm.%d max.%d\n",answerind,lastanswerind,answerindmask,vars->CLspaces[answerind],vars->weekinds[answerind],vars->nohwm[answerind],max_nohwm);
            if ( vars->hwmperc[answerind] != 0 )
            {
                nosum += vars->nohwm[answerind];
                pcount++, psum += vars->hwmperc[answerind];
            }
            //printf("answerind.%d\n",answerind);
            if ( vars->len[answerind] == 0 || vars->CLspaces[answerind] == 0 || (vars->nohwm[answerind] > min_nohwm && vars->hwmperc[answerind] > ((answerind==0) ? HWMPERC_THRESHOLD0 : HWMPERC_THRESHOLD)) )
            {
                inactives[answerind] = 1;
                continue;
            }
            if ( vars->nohwm[answerind] < max_nohwm )
            {
                numactive++;
                if ( vars->numIt[answerind]++ == 0 )
                {
                    for (i=0; i<numfeatures; i++)
                        if ( vars->CLspaces[answerind]->W[i] != 0 )
                            break;
                    if ( i == numfeatures )
                        skipflags[answerind] = 1;
                }
                ptr = vars->CLspaces[answerind];
                weekinds = vars->weekinds[answerind];
                //printf("start iter %p %p\n",ptr,weekinds);
                start_ocas_iter(vars,vars->c,answerind);
                numthreads = vars->numthreads;
                if ( skipflags[answerind] != 0 )
                {
                    for (i=0; i<vars->len[answerind]; i++)
                    {
                        if ( (y= vars->answers[(weekinds[i]-vars->starti)*TRADEBOTS_NUMANSWERS + answerind]) != 0.f )
                        {
                            ptr->output_pred[i] = 0;
                            add_newcut_entry(vars,answerind,new_cut,i,weekinds[i],y);
                        }
                    }
                    fprintf(stderr,"skip %d.A%02d cuts +%d -%d, ",c_to_refc(vars->c),answerind,vars->numposcuts[answerind],vars->numnegcuts[answerind]);
                }
                else
                {
                    startmilli = OS_milliseconds();
                    //printf("%s ocas_calc_outputs.A%d len.%d | numthreads.%d\n",CONTRACTS[c_to_refc(c)],answerind,vars->len[answerind],numthreads);
                    STocas_calc_outputs(vars,vars->c,answerind,ptr->output_pred,ptr->old_output,ptr->W,vars->W0[answerind],numfeatures,weekinds,vars->len[answerind]);
                    //ocas_calc_outputs(PTRS,numthreads,vars,c,answerind,ptr->output_pred,ptr->old_output,ptr->W,vars->W0[answerind],numfeatures,weekinds,vars->len[answerind]);
                    vars->output_time += (OS_milliseconds() - startmilli);
                    if ( Method != 0 )
                    {
                        startmilli = OS_milliseconds();
                        //printf("%d calc_ocas_strategy.A%d len.%d | numthreads.%d\n",c_to_refc(vars->c),answerind,vars->len[answerind],numthreads);
                        calc_ocas_strategy(vars,answerind,vars->C,numfeatures,vars->maxlen,weekinds,new_cut,ptr->W,ptr->oldW,ptr->output_pred,ptr->old_output,hpfb);
                        vars->w_time += (OS_milliseconds() - startmilli);
                    }
                    finish_ocasiter(answerind,vars,vars->C);
                }
                //printf("%s calc ocas_add_newcuts.A%d poscuts.%d negcuts.%d | numthreads.%d\n",CONTRACTS[c_to_refc(c)],answerind,vars->numposcuts[answerind],vars->numnegcuts[answerind],vars->numthreads);
                startmilli = OS_milliseconds();
                //if ( vars->nohwm[answerind] > 13 )
                //	numthreads = vars->numthreads;///MAIN_MAXCORES;
                memset(ptr->new_a,0,sizeof(ptr->new_a));
                //ocas_add_newcuts(PTRS,numthreads,vars,answerind,numfeatures,weekinds,new_cut,vars->numposcuts[answerind]+vars->numnegcuts[answerind],ptr->W,ptr->new_a);
                STocas_add_newcuts(vars,answerind,numfeatures,weekinds,new_cut,vars->numposcuts[answerind]+vars->numnegcuts[answerind],ptr->W,ptr->new_a);
                vars->add_time += (OS_milliseconds() - startmilli);
//printf("done %d calc ocas_add_newcuts.A%d poscuts.%d negcuts.%d | good.%d bad.%d\n",c_to_refc(vars->c),answerind,vars->numposcuts[answerind],vars->numnegcuts[answerind],vars->good[answerind],vars->bad[answerind]);
            } else inactives[answerind] = 1;//, printf("maxnohwm.%d\n",max_nohwm);
        }
        startmilli = OS_milliseconds();
        for (answerind=0; answerind<lastanswerind; answerind++)
        {
            if (  inactives[answerind] != 0 )
                continue;
            netcuts = (vars->numposcuts[answerind] - vars->numnegcuts[answerind]);
            cutlen = (vars->numposcuts[answerind] + vars->numnegcuts[answerind]);
            if ( vars->nohwm[answerind] < lwm )
                lwm = vars->nohwm[answerind];
            ocas_update_Lspace(vars,answerind,netcuts,cutlen,numfeatures,vars->C,0.,vars->QPSolverTolRel);
        }
        vars->qp_solver_time += (OS_milliseconds() - startmilli);
    }
    if ( pcount != 0 )
        printf("numactive.%d %.0f | ave perf %f%% | ave nohwm %.1f\n",numactive,pcount,psum/pcount,nosum/pcount);
    return(numactive);
}

static inline int init_ocas_vars(int numthreads,int selector,long answerindmask,struct ocas_vars *vars,int c,double C,int numfeatures,int maxlhs,int maxlen,int len,double *answerabsave,int *posA,int *negA)
{
    int answerind,lastanswerind,retval = 0;
    lastanswerind = TRADEBOTS_NUMANSWERS;
    vars->maxlen = maxlen;
    vars->numthreads = numthreads;
    vars->selector = selector;
    //printf("init_ocas_vars lastanswerind.%d\n",lastanswerind);
    for (answerind=0; answerind<lastanswerind; answerind++)
    {
        //printf("A%d.len_%d ",answerind,vars->len[answerind]);
        if ( vars->len[answerind] > 0 )//&& (answerindmask == -1L || ((1L<<answerind) & answerindmask) != 0) )
        {
            vars->refc = c_to_refc(c); vars->c = c; vars->C = C;
            vars->numfeatures = numfeatures; vars->maxlhs = maxlhs;
            if ( vars->CLspaces[answerind] == 0 )
                vars->CLspaces[answerind] = myaligned_alloc(sizeof(*vars->CLspaces[answerind]));
            vars->answerabsaves[answerind] = answerabsave[answerind];
            vars->posA[answerind] = posA[answerind]; vars->negA[answerind] = negA[answerind];
            if ( vars->lhs[answerind] == 0 )
                vars->lhs[answerind] = myaligned_alloc(sizeof(*vars->lhs[answerind]) + numfeatures*maxlhs*sizeof(double));
            vars->maxiters[answerind] = QPSOLVER_MINITER;  vars->trn_err[answerind] = vars->len[answerind]; vars->Q_P[answerind] = 0.5*vars->sq_norm_W[answerind] + C*vars->len[answerind];
            vars->perc[answerind] = vars->hwmperc[answerind] = vars->dist[answerind] = vars->hwmdist[answerind] = 0.; vars->numIt[answerind] = 0;
            //printf("init.A%d %d | %p %p weekinds.%p\n",answerind,vars->len[answerind],vars->CLspaces[answerind],vars->lhs[answerind],vars->weekinds[answerind]);
        }
    }
    //printf("mask.%lx init_ocas_vars selector.%d weekinds[0].%p\n",answerindmask,selector,vars->weekinds[0]);
    return(retval);
}

void ocas_init(struct ocas_vars *vars,int32_t c,int32_t numfeatures,int32_t starti,int32_t endi)
{
    struct ocas_CLbuffers *ptr; struct ocas_lhsbuffers *lhs;
    int32_t nonz,weekind,answerind; double answer,y;
    if ( numfeatures < 0 )
        return;
    vars->maxlhs = MAX_OCAS_LHS;
    vars->numfeatures = numfeatures;
    vars->maxlen = (endi - starti + 1);
    vars->C = 1.;
    vars->c = c;
    vars->TolRel = 0.01;
    vars->TolAbs = 0.0;
    vars->QPSolverTolRel = vars->TolRel*0.5;
    vars->QPSolverTolAbs = vars->TolAbs*0.5;
	vars->MaxTime = OCAS_INFINITY;
    vars->QPBound = 0.0;
    memset(vars->posA,0,sizeof(vars->posA));
    memset(vars->negA,0,sizeof(vars->negA));
    memset(vars->answeraves,0,sizeof(vars->answeraves));
    memset(vars->answerabsaves,0,sizeof(vars->answerabsaves));
    memset(vars->firstweekinds,0,sizeof(vars->firstweekinds));
    vars->starti = starti;
    vars->answers = calloc(TRADEBOTS_NUMANSWERS,sizeof(vars->answers)*vars->maxlen);
    vars->features = calloc(vars->maxlen,sizeof(*vars->features));
    for (answerind=0; answerind<TRADEBOTS_NUMANSWERS; answerind++)
        vars->weekinds[answerind] = calloc(vars->maxlen,sizeof(*vars->weekinds[answerind]));
    for (weekind=starti; weekind<=endi; weekind++)
    {
        if ( (vars->features[weekind - starti]= get_features(numfeatures,c,weekind)) == 0 )
            continue;
        for (answerind=0; answerind<TRADEBOTS_NUMANSWERS; answerind++)
        {
            if ( (vars->posA[answerind]+vars->negA[answerind]) >= vars->maxlen )
                continue;
            if ( (y= get_yval(&answer,0,weekind,c,answerind)) != 0.f )
            {
                vars->answers[(weekind-starti)*TRADEBOTS_NUMANSWERS + answerind] = y;
                vars->weekinds[answerind][vars->len[answerind]++] = weekind;
                if ( vars->posA[answerind]+vars->negA[answerind] == 0 )
                    vars->firstweekinds[answerind] = weekind;
                vars->answeraves[answerind] += answer;
                if ( answer > 0 )
                {
                    vars->posA[answerind]++;
                    vars->answerabsaves[answerind] += answer;
                }
                else if ( answer < 0 )
                {
                    vars->negA[answerind]++;
                    vars->answerabsaves[answerind] -= answer;
                }
            }
        }
    }
  	for (answerind=0; answerind<TRADEBOTS_NUMANSWERS; answerind++)
		if ( (nonz= (vars->posA[answerind]+vars->negA[answerind])) != 0 )
		{
			vars->answerabsaves[answerind] /= nonz;
            vars->answeraves[answerind] /= nonz;
			printf("A%02d.(%9.6f %d %d) ",answerind,vars->answerabsaves[answerind],vars->posA[answerind],vars->negA[answerind]);
        }
    init_ocas_vars(1,0,-1,vars,c,vars->C,numfeatures,MAX_OCAS_LHS,vars->maxlen,vars->maxlen,vars->answerabsaves,vars->posA,vars->negA);
    for (answerind=0; answerind<TRADEBOTS_NUMANSWERS; answerind++)
    {
        //if ( answerindmask != -1 && ((1L<<answerind) & answerindmask) == 0 )
        //    continue;
        //printf("finish A%d len.%d\n",answerind,vars->len[answerind]);
        lhs = vars->lhs[answerind];
        ptr = vars->CLspaces[answerind];
        //printf("%d.A%d call init ocas vars weekinds[0] %p numfeatures.%d (%p %p)\n",c_to_refc(vars->c),answerind,vars->weekinds[0],numfeatures,lhs,ptr);
        if ( lhs == 0 || ptr == 0 )
            continue;
        vars->numlhs[answerind] = 0;//init_full_A(lhs->full_A,vars->numfeatures,c,answerind,models);
        memset(ptr->W,0,sizeof(*ptr->W) * numfeatures);
        memset(ptr->oldW,0,sizeof(*ptr->oldW) * numfeatures);
        vars->W0[answerind] = vars->oldW0[answerind] = 0;
#ifndef DISABLE_EXISTINGMODEL
        double init_model(double *percp,double *W,double *oldW,int c,int answerind,int numfeatures);
        vars->W0[answerind] = init_model(&vars->hwmperc[answerind],ptr->W,ptr->oldW,c,answerind,vars->numfeatures);
        if ( _dbufave(ptr->W,numfeatures) != 0 )
            validate_ocas_model(vars,answerind,ptr->output_pred,ptr->old_output,vars->weekinds[answerind],vars->len[answerind],ptr->W,vars->W0[answerind],numfeatures,1);
#endif
        //printf("%s.A%d call init ocas vars weekinds[0] %p\n",CONTRACTS[c_to_refc(c)],answerind,vars->weekinds[0]);
    }
    vars->output_time = vars->sort_time = vars->w_time = vars->qp_solver_time = vars->ocas_time = vars->add_time = 0;
    vars->startweekind = starti; vars->endweekind = endi;
}

int32_t ocas_gen(int32_t c,int32_t numfeatures,int32_t starti,int32_t endi)
{
    int32_t i; struct ocas_vars *vars = calloc(1,sizeof(*vars));
    ocas_init(vars,c,numfeatures,starti,endi);
    for (i=0; i<10; i++)
        ocas_iter(vars,3);
    ocas_purge(vars);
    return(0);
}
#endif
