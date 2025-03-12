////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : *** VARDAAN KAPOOR ***
//   Last Modified : *** 3/12/2025 ***
//
#include <compsci642_log.h>
#include "cs642-cryptanalysis-support.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <float.h>
#include <math.h>
#include <ctype.h>
#define TEMP_INITIAL 100.0    // Initial temperature for simulated annealing
#define TEMP_DECAY 0.99       // Decay factor for temperature
#define ALPHABET_SIZE 26
#define MAX_ITERATIONS 10000
#define MAX_TEXT 10000
#define MAX_NGRAMS 5000  // Limit the number of unique n-grams
#define MAX_N 4  // Maximum n-gram size (bigram = 2, trigram = 3)
#define kP 0.067  // Expected index of coincidence for English text
#define kR 1.0 / 26.0  // Expected index of coincidence for random text
typedef struct {
  char ngram[MAX_N + 1];  // Stores n-grams (up to trigrams)
  double count;  // Frequency of occurrence
} NGramFreq;
typedef struct {
  char ngram[5];  // 4-gram + null terminator
  double frequency;
} FourGramEntry;
NGramFreq expected_ngrams[MAX_NGRAMS];//this is the hashmap which stores the n-grams and their frequencies we get from the dictionary
int total_expected_ngrams;
int totalNotUnique_expected_ngrams;
FourGramEntry fourGrams[MAX_NGRAMS];//this hashmap is only for storing the 4-grams and their frequencies we get from the candidate plaintext which we get by decrypting the given ciphertext by our candidate key
int fourGramCount = 0;
int countSimilar=0;
int countPlaintextFourGrams=0;

int cs642StudentInit(void) {
compute_expected_ngram_frequencies(expected_ngrams, &total_expected_ngrams,&totalNotUnique_expected_ngrams, 4);
  return (0);
}
/**
 * @brief Compute the frequency of each letter in the dictionary
 * @param computed_freq The array to store the frequency of each letter
 * @return void
 */
void compute_letter_frequencies(double *computed_freq) {
  //POINT 1
  int dict_size = cs642GetDictSize();  // Get dictionary size
  //POINT 2
  int total_letters = 0;
  //POINT 3
  // Loop through each word in the dictionary
  for (int i = 0; i < dict_size; i++) {
      DictWord entry = cs642GetWordfromDict(i);
      char *word = entry.word;
      int word_freq = entry.count;  // How many times this word appears
      //POINT 4
      // Count letter occurrences
      for (int j = 0; word[j] != '\0'; j++) {
          if (word[j] >= 'A' && word[j] <= 'Z') {
              computed_freq[word[j] - 'A'] += word_freq;
              total_letters += word_freq;
          }
      }
  }
    //POINT 5
  // Normalize frequencies (convert counts to probabilities)
  for (int i = 0; i < ALPHABET_SIZE; i++) {
      computed_freq[i] /= (total_letters);  // Avoid division by zero
  } 
}
void decrypt_rotx(char *ciphertext, int clen, char *plaintext, int shift) {
  //POINT 1
  for (int i = 0; i < clen; i++) {
      if (ciphertext[i]!=' ') {
          plaintext[i] = ((ciphertext[i] - 'A' - shift + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A';
      } else {
          plaintext[i] = ciphertext[i];  // Preserve spaces and punctuation
      }
  }
  //POINT 2
  plaintext[clen] = '\0';  // Null-terminate the plaintext
}
/**
 * @brief Compute the frequency of each letter in the ciphertext
 * @param text The ciphertext to analyze
 * @param len The length of the ciphertext
 * @param freq The array to store the frequency of each letter
 * @param total_letters The total number of letters in the ciphertext
 * @return void
 */
void compute_ciphertext_frequencies(char *text, int len, int freq[ALPHABET_SIZE], int *total_letters) {
  //POINT 1
  for (int i = 0; i < ALPHABET_SIZE; i++) freq[i] = 0;
  *total_letters = 0;
  int countSpaces=0;
  //POINT 2
  for (int i = 0; i < len; i++) {
      if ((text[i])!=' ') {
          freq[text[i] - 'A']++;
          (*total_letters)++;
      }
      else{
        countSpaces++;
      }
  }
}
/**
 * @brief Compute the chi-squared value for a set of observed letter frequencies
 * @param computed_freq The computed letter frequencies from the dictionary
 * @param freq The observed letter frequencies from the candidate plaintext
 * @param total_letters The total number of letters in the candidate plaintext
 * @return The chi-squared value
 */
double compute_chi_squared(double *computed_freq,int freq[ALPHABET_SIZE], int total_letters) {
  //POINT 1
  double chi_sq = 0.0;
  //POINT 2
  for (int i = 0; i < ALPHABET_SIZE; i++) {
      double expected = total_letters * computed_freq[i];  // E_i = N * P_i
      double observed = freq[i];
      //POINT 3
      // Compute Chi-Squared contribution for this letter
      chi_sq += ((observed - expected) * (observed - expected)) / (expected);
  }
  return chi_sq;
}
  /**
   * @brief Compute the chi-squared value for a set of observed 4-grams
   * @param observed_ngrams The observed 4-grams hashmap from the candidate plaintext
   * @param total_observed The total number of observed 4-grams in the hashmap of these 4 grams we get from the candidate plaintext
   * @return The chi-squared value
   */
  double compute_chi_square_4gram(FourGramEntry *observed_ngrams, int total_observed) {
    double chi_sq = 0.0;int count=0;
    for (int i = 0; i < total_observed; i++) {
        for (int j = 0; j < total_expected_ngrams; j++) {
            if (strcmp(observed_ngrams[i].ngram, expected_ngrams[j].ngram) == 0) {
          //    countSimilar++;
                double expected = expected_ngrams[j].count;
                double observed = observed_ngrams[i].frequency;
                // printf("chi square value is %f\n",((observed - expected) * (observed - expected)) / expected);
                chi_sq += ((observed - expected) * (observed - expected)) / expected;
                count++;
                break;
            }
        }
    }
   //printf("count is %d\n",count);
    return chi_sq==0?DBL_MAX:chi_sq;
}
// double perform_chi_square_test(const char *plaintext) {
//   FourGramEntry observed_ngrams[MAX_NGRAMS];
//   int total_observed;
//   extract_fourgrams(plaintext, observed_ngrams, &total_observed);
//   return compute_chi_square_4gram(observed_ngrams, total_observed);
// }
int cs642PerformROTXCryptanalysisByChiSquare(char *ciphertext, int clen, char *plaintext,
  int plen, uint8_t *key) {
    //POINT A
    // printf("ciphertext input %s\n",ciphertext);//print the input ciphertext
    // printf("clen is %d\n",clen);//print the length of the ciphertext
    // printf("plaintext input %s\n",plaintext);//print the input plaintext
    // printf("plen is %d\n",plen);//print the length of the plaintext
    // printf("key input %s\n",key);//print the input key
    
    double computed_freq[ALPHABET_SIZE] = {0};
    //POINT B
    compute_letter_frequencies(computed_freq);  // Compute letter probabilities from dictionary
      //POINT C
      int best_shift = 0;
      double min_chi_sq = DBL_MAX;
  
      // Try all possible shifts (ROTX 1-25)
      for (int shift = 1; shift <= 25; shift++) {
          char decrypted[clen + 1];
          decrypt_rotx(ciphertext, clen, decrypted, shift);
          //POINT D
          int freq[ALPHABET_SIZE];
          int total_letters;
          compute_ciphertext_frequencies(decrypted, clen, freq, &total_letters);
          //POINT E
          double chi_sq = compute_chi_squared(computed_freq,freq, total_letters);
          //POINT F
          // Find the shift with the lowest chi-squared value
          if (chi_sq < min_chi_sq) {
              min_chi_sq = chi_sq;
              best_shift = shift;
          }
      }
      //POINT G
      // Set the recovered key
      *key = best_shift;
  
      // Decrypt with the best shift
      decrypt_rotx(ciphertext, clen, plaintext, best_shift);
  
      //printf("Recovered ROTX key: %d\n", best_shift);
      // printf("Decrypted text: %s\n", plaintext);
  
      return 0;

  }
int cs642PerformROTXCryptanalysisByBruteForce(char *ciphertext, int clen, char *plaintext,
  int plen, uint8_t *key) {
  //POINT A
  // printf("ciphertext input %s\n",ciphertext);//print the input ciphertext
  // printf("clen is %d\n",clen);//
  // printf("plaintext input %s\n",plaintext);//print the input plaintext
  // printf("plen is %d\n",plen);//print the length of the plaintext
  // printf("key input %s\n",key);//print the input key
  //POINT B
  int best_shift = 0;//counter for the best shift
    int max_matches = 0;//counter for the max matches
    char decrypted[plen];//decrypted text
    //POINT C
    // Try all possible ROTX shifts (1-25)
    for (int shift = 1; shift <= 25; shift++) {//loop through all possible shifts
        for (int i = 0; i < clen; i++) {//loop through the ciphertext
            if (ciphertext[i] == ' ') {//if the character is a space
                decrypted[i] = ' ';//set the decrypted text to a space
            } else {//if the character is not a space
                decrypted[i] = ((ciphertext[i] - 'A' - shift + 26) % 26) + 'A';//decrypt the text(only one character at a time)
            }
        }
        decrypted[clen] = '\0';//set the last character to null of the decrypted text
        //POINT D
        // Check how many dictionary words match
        int match_count = 0;//counter for the match count
        int dict_size = cs642GetDictSize();//get the size of the dictionary
        for (int j = 0; j < dict_size; j++) {//loop through the dictionary
            DictWord word = cs642GetWordfromDict(j);//get the word from the dictionary
            if (strstr(decrypted, word.word) != NULL) {//if the word is found in the decrypted text
                match_count += word.count;//increment the match count
            }
        }
        // Update best shift if more words match
        if (match_count > max_matches) {//if the match count is greater than the max matches
            max_matches = match_count;//set the max matches to the match count
            best_shift = shift;//set the best shift to the shift
            strcpy(plaintext, decrypted);//copy the decrypted text to the plaintext
        }
    }
    //POINT E
    // Set the key to the best shift found
    *key = best_shift;//set the key to the best shift found
    //printf("Recovered ROTX key: %d\n", best_shift);//print the recovered ROTX key
    return 0;//return 0
  }
int cs642PerformROTXCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key) {

  //method 1
  return cs642PerformROTXCryptanalysisByChiSquare(ciphertext, clen, plaintext, plen, key);
  //method 2
  //return cs642PerformROTXCryptanalysisByBruteForce(ciphertext, clen, plaintext, plen, key);
 
}



/**
 * @brief Compute the index of coincidence for a given text
 * @param freq The frequency of each letter in the text
 * @param total The total number of letters in the text
 * @return The index of coincidence
 */
double compute_index_of_coincidence(int *freq, int total) {
  double ic = 0.0;
  for (int i = 0; i < ALPHABET_SIZE; i++) {
      ic += (freq[i] * (freq[i] - 1));
  }
  ic /= (total * (total - 1));
  return ic;
}

void decrypt_vigenere(char *ciphertext, int clen, char *plaintext, int keylen, char *key) {
  for (int i = 0; i < clen; i++) {
      if (ciphertext[i]!=' ') {
          int shift = key[i % keylen] - 'A';
          plaintext[i] = ((ciphertext[i] - 'A' - shift + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A';
      } else {
          plaintext[i] = ciphertext[i]; // Preserve spaces
      }
  }
  plaintext[clen] = '\0'; // Null-terminate plaintext
}
int getVigenereKey(char *ciphertext, int clen, char *plaintext,
  int plen, char *key)
  {
    //POINT A
    double kp = 0.067; // Coincidence index of English text
  double kr = 1.0 / 26.0; // Random letter probability
  double bestFriedmanValue = DBL_MAX; // Start with a large number
  int best_guess = 6; // Default key length guess
  //POINT B
  for (int key_len = 6; key_len <= 11; key_len++) {//loop through all the values we can have for #of columns or length of the key
    double sumFriedmanValue=0;
    double averageFriedmanValue=0;
    //POINT C
    for(int i=0;i<key_len;i++)//loop for the number of columns we have chose above for the value of the key_len
    {
      int freq[ALPHABET_SIZE] = {0};//initialize the frequency array to 0(26 characters)
      int total = 0;//initialize the total to 0 as it will store the total number of characters in a particular column
      //POINT D
      char column[clen];
      int column_len=0;
      int count=0;
      for(int j=i;j<clen;j+=key_len)
      {
        column[column_len++]=ciphertext[j];
        if(ciphertext[j]>='A' && ciphertext[j]<='Z')
        {
          freq[ciphertext[j]-'A']++;
          total++;
        }
        else{
          count++;
        }
      }
      column[column_len]='\0';
      //POINT E
      double k0 = compute_index_of_coincidence(freq, total);//compute the index of coincidence
      //POINT F
      double friedmanValue=(kp-kr)/(k0-kr);//compute the friedman value    
      sumFriedmanValue+=friedmanValue;//add the friedman value to the sum of friedman values
    }
    //POINT G
    averageFriedmanValue=sumFriedmanValue/key_len;//compute the average friedman value
    if(averageFriedmanValue<bestFriedmanValue)//if the average friedman value is greater than the best friedman value
    {
      bestFriedmanValue=averageFriedmanValue;//set the best friedman value to the average friedman value
      best_guess=key_len;//set the best guess to the key length
    }
  }
  //POINT H
  return best_guess;//return the best guess
  }
  void split_ciphertext_into_columns(char *ciphertext, int clen, int keySize, char columns[][clen]) {
    for (int i = 0; i < keySize; i++) {
      columns[i][0] = '\0';  // Null terminate to start empty
  }
  // Fill columns by taking every N-th letter
  for (int i = 0; i < clen; i++) {
      int col_index = i % keySize;  // Determine which column to put the character in
      int len = strlen(columns[col_index]);  // Current length of that column
      columns[col_index][len] = ciphertext[i];  // Add character
      columns[col_index][len + 1] = '\0';  // Null terminate
  }
}
void getCandidateKeyColumns(char *ciphertext, int clen, int keySize, char columns[][clen / keySize + 1]) {
int currentRow = 0;
for (int i = 0; i < clen; i++) {
columns[i % keySize][currentRow] = ciphertext[i];
if ((i % keySize) == (keySize - 1)) {
currentRow++;
}}
for(int j = 0; j < keySize; j++) {
columns[j][currentRow] = '\0';
}
}
/**
 * @brief Compute the index of coincidence for a given text
 * @param text the text
 * @param length The total number of letters in the text
 * 
 */
double computeICValue(char *text, int length) {
int freqArray[26] = {0};
double k0Value = 0.0;
for(int i = 0; i < length; i++) {
if(text[i]!=' ') {
freqArray[text[i] - 'A']++;
}
}
for(int i = 0; i < 26; i++) {
k0Value += freqArray[i] * (freqArray[i] - 1);
}
k0Value = k0Value / (length * (length - 1));
return k0Value;
}
//perform friedman to estimate key length
int performFT(char *ciphertext, int clen) {
double bestAvgValue = 0.0;
double bestKeyLength = 6;
for(int keySize = 6;keySize <= 11; keySize++) {
double sum = 0.0;
char columns[keySize][clen / keySize + 1];
getCandidateKeyColumns(ciphertext, clen, keySize, columns);
for(int i = 0; i < keySize; i++) {
sum += computeICValue(columns[i], strlen(columns[i]));
}
sum = sum / keySize;
if(fabs(sum-kP)<fabs(bestAvgValue-kP)) {  
bestAvgValue = sum;
bestKeyLength = keySize;
}
}
//try key lengths from 6 - 11
return bestKeyLength;
}
void computeExpectedFrequencies(double exepectedFrequency[26]) {
int letterCounts[26] = {0};
int totalLetters = 0;
//get dictionary size
int dictionarySize = cs642GetDictSize();
//iterate through all word in dictionary
for (int i = 0; i < dictionarySize; i++) {
DictWord wordEntry = cs642GetWordfromDict(i);
char *word = wordEntry.word;
//count letter occurrences
for (int j = 0; word[j] != '\0'; j++) {
if (isalpha(word[j])) {
letterCounts[word[j] - 'A']++;
totalLetters++;
}
}
}
//convert counts to probabilities (percentage)
for (int i = 0; i < 26; i++) {
exepectedFrequency[i] = (totalLetters > 0) ? (letterCounts[i] * 100.0 / totalLetters) : 0.0;
}
}
/**
 * @brief Decrypt a single column using Vigenere cipher
 * @param column The column to decrypt
 * @param length The length of the column
 * @param keyShift The best shift found
 * @return void
 */
void decryptColumn(char *column, int length, int *keyShift) {
int bestShift = 0;
double bestChiSquared = 1e9; //arbitrarily large value
//compute expected letter frequencies from dictionary
double exepectedFrequency[26];
computeExpectedFrequencies(exepectedFrequency);
//try 26 shifts
for (int shift = 0; shift < 26; shift++) {
int letterCounts[26] = {0};
//count letter frequencies in shifted texts
for (int i = 0; i < length; i++) {
if (column[i]!=' ' && isalpha(column[i])) {
char decoded = ((column[i] - 'A' - shift + 26) % 26) + 'A';
letterCounts[decoded - 'A']++;
}
}
double chiSquared = 0.0;
for (int i = 0; i < 26; i++) {
double observed = letterCounts[i];
double expected = exepectedFrequency[i] * length / 100.0; //since it was a percent earlier
if (expected > 0) {
chiSquared += ((observed - expected) * (observed - expected) / expected);
}
}
//select shift with lowest chi-square value
if (chiSquared < bestChiSquared) {
bestChiSquared = chiSquared;
bestShift = shift;
}
}
*keyShift = bestShift; //store best shift
}
void computeDictFreq(double dictionaryFrequencies[26])
{
  int characterFrequency[26] = {0};
  int totalCharacters = 0;
  int totalUniqueWords= cs642GetDictSize();
  for(int i=0;i<totalUniqueWords;i++)
  {
    DictWord word = cs642GetWordfromDict(i);
    char *actualWord = word.word;
    int wordFrequency = word.count;
    for(int j=0;actualWord[j]!='\0';j++)
    {
      if(actualWord[j]!=' ')
      {
        characterFrequency[actualWord[j]-'A']++;
        totalCharacters++;
      }
    } 
  }
  for(int i=0;i<26;i++)
  {
    dictionaryFrequencies[i] = (totalCharacters > 0) ? (characterFrequency[i] * 100.0 / totalCharacters) : 0.0;
  }
}

/**
 * @brief Decrypt a single column using Vigenere cipher
 * @param column The column to decrypt
 * @param length The length of the column
 * @param candidateOffset The best shift found
 * @return void
 */
void decryptIthColumn(char *column, int length, int *candidateOffset) {
  int bestOffset = 0;
  double bestChiSquared = DBL_MAX;
  double dictionaryFrequencies[26] = {0};
  computeDictFreq(dictionaryFrequencies);
  for (int candidateShift = 0; candidateShift < 26; candidateShift++) {
    int characterCounter[26] = {0};
    //count letter frequencies in shifted texts
    for (int i = 0; i < length; i++) {
      if (column[i]!=' ') {
        char changedChar = ((column[i] - 'A' - candidateShift + 26) % 26) + 'A';
        characterCounter[changedChar - 'A']++;
      }
  }
    //compute chi-squared score
    double chiSquared = 0.0;
    for (int i = 0; i < 26; i++) {
      double seenFreq = characterCounter[i];
      double hypothesisValue = dictionaryFrequencies[i] * length / 100.0; //since it was a percent earlier
      if (hypothesisValue > 0) {
        chiSquared += ((seenFreq - hypothesisValue) * (seenFreq - hypothesisValue) / hypothesisValue);
      }
    }
    //select shift with lowest chi-square value
    if (chiSquared < bestChiSquared) {
      bestChiSquared = chiSquared;
      bestOffset = candidateShift;
    }
  }
  *candidateOffset = bestOffset; //store best shift
}

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {
  
  int keySize = performFT(ciphertext, clen);
  char columns[keySize][clen / keySize + 1];
  getCandidateKeyColumns(ciphertext, clen, keySize, columns);
  int storeIndividualOffsets[keySize];
  for (int i = 0; i < keySize; i++) {
    decryptIthColumn(columns[i], strlen(columns[i]), &storeIndividualOffsets[i]);
    key[i] = 'A' + storeIndividualOffsets[i];
  } 
  key[keySize] = '\0';
  decrypt_vigenere(ciphertext, clen, plaintext, keySize, key);
  return 0;
}

/**
 * @brief Swap two positions in a key
 * @param key The key to modify
 * @param i The first position
 * @param j The second position
 * @return void
 */
void swap2Positions(char *key, int i, int j) {
  char temp = key[i];
  key[i] = key[j];
  key[j] = temp;
}
/**
 * @brief Compute the expected n-gram frequencies from the dictionary(we create a hash map which stores this matrix of a particular 4 gram and its frequency in dictionary)
 * @param freqTable The table to store the n-gram frequencies
 * @param total_ngrams The total number of unique n-grams
 * @param n The size of the n-grams-we only test here for 4 grams so use n=4 only
 */
void compute_expected_ngram_frequencies(NGramFreq *freqTable, int *total_ngrams,int *totalNotUnique_expected_ngrams, int n) {
  int dict_size = cs642GetDictSize();
  *total_ngrams = 0;
  for (int i = 0; i < dict_size; i++) {
      DictWord entry = cs642GetWordfromDict(i);
      char *word = entry.word;
      int word_freq = entry.count;
      int len = strlen(word);
      for (int j = 0; j <= len - n; j++) {
          char ngram[MAX_N + 1] = {0};
          strncpy(ngram, word + j, n);
          ngram[n] = '\0';  // Null-terminate
          (*totalNotUnique_expected_ngrams)+=word_freq;
          // Search if n-gram exists in the table
          int found = 0;
          for (int k = 0; k < *total_ngrams; k++) {
              if (strcmp(freqTable[k].ngram, ngram) == 0) {
                  freqTable[k].count += word_freq;
                  found = 1;
                  break;
              }
          }
          // If new n-gram, add to table
          if (!found && *total_ngrams < MAX_NGRAMS) {
              strcpy(freqTable[*total_ngrams].ngram, ngram);
              freqTable[*total_ngrams].count = word_freq;
              (*total_ngrams)++;
          }
      }
  }
  for(int i=0;i<*total_ngrams;i++)
  {
    freqTable[i].count=freqTable[i].count/(*totalNotUnique_expected_ngrams);
  }
}
/**
 * @brief Add or update a 4-gram in the mapping
 * @param ngram The 4-gram to add or update
 */
void addFourGram(char *ngram) {//this function adds the 4-gram to the hash map which stores the 4-grams and their frequencies-ngram is the 4-gram we want to add
  for (int i = 0; i < fourGramCount; i++) {//loop through the 4-grams we have stored in the hash map so that we can compare this newly candidate 4gram to these esixting ones
      if (strcmp(fourGrams[i].ngram, ngram) == 0) {//if the 4-gram we are trying to add is already present in the hash map(we use string compare method to compare the strings)
          fourGrams[i].frequency++;//increment the frequency of this 4-gram as we have found this 4-gram again(we already have this 4 gram in hashmap so increase frequency)
          return;//return as we have found the 4-gram in the hashmap so we have incremented the frequency of this 4-gram
      }
  }
  // New 4-gram entry
  strcpy(fourGrams[fourGramCount].ngram, ngram);//if we don't find this 4-gram in the hashmap then add this 4-gram to the hashmap as a new unique member of the hash map
  fourGrams[fourGramCount].frequency = 1;//set the frequency of this 4-gram to 1 as this is the first time we are seeing this 4-gram
  fourGramCount++;//increment the count of the 4-grams in the hashmap(this counts the number of unique 4 grams in the hash map-so the number of keys in the hash map)
}
/**
 * @brief Extract 4-grams from a single word
 * @param word The word to extract 4-grams from
 */

void extractFourGramsFromWord(char *word) {
  int len = strlen(word);//getting the length of the word
    // Ignore words smaller than 4 characters
 if (len < 4) return;//if lenfth of the word is less than 4 then return because we have a word lesser than 4 so it can't give us any 4 gram as length<4
  for (int i = 0; i <= len - 4; i++) {//loop through the word(whole length of the word -4 as the last 4 gram will start from len-4) till the length of the word-4
      char temp[5];//temporary array to store the 4-gram(this character array will store the candidate 4 gram we extract using a sliding window of 4 characters)
      strncpy(temp, &word[i], 4);//copy the 4 characters(which make up this potential candidate 4 gram) from the word to the temp array which stores this 4 gram
      temp[4] = '\0';  // Null-terminate the 4-gram character array
      addFourGram(temp);//add this 4-gram to the 4-gram storing hash map which stores the 4-grams and their frequencies(pertaining to each of the candidate keys)
      countPlaintextFourGrams++;//increment the count of the 4-grams in the plaintext(this counts the total number of 4-grams in the plaintext)
  }
}

// Function to process text word by word
/**
 * @brief Extract 4-grams from the text
 * @param text The text to extract 4-grams from
 */
void extractFourGrams(char *text) {//text is the plaintext which we got from the candidate random key we are checking
  char *token = strtok(text, " ");  // Split by spaces
  while (token != NULL) {//till the time we are getting a word from the token character array
    extractFourGramsFromWord(token);//extract 4-grams from the word we got from the character array
    token = strtok(NULL, " ");//get the next word from the token character array
  }
}

/**
 * @brief Apply log probability to the 4-grams
 * @return The log probability of the 4-grams
 */
 double applyLogProbability() {
  double prob=0;int found=0;
  for (int i = 0; i < fourGramCount; i++) {
    found=0;
    for(int j=0;j<total_expected_ngrams;j++)
    {
      if(strcmp(fourGrams[i].ngram,expected_ngrams[j].ngram)==0)
      {
        prob+=(log(expected_ngrams[j].count))*fourGrams[i].frequency;
        found=1;
        break;
      }
    }
    if(found<1){
      prob+=log(0.1)*fourGrams[i].frequency;
    }
  }
  return prob;
}
double compute_log_probability(FourGramEntry *observed_ngrams, int total_observed) {
  double log_prob = 0.0;
  for (int i = 0; i < total_observed; i++) {
      for (int j = 0; j < total_expected_ngrams; j++) {
          if (strcmp(observed_ngrams[i].ngram, expected_ngrams[j].ngram) == 0) {
              log_prob += log(expected_ngrams[j].count) * observed_ngrams[i].frequency;
              break;
          }
      }
  }
  return log_prob;
}
/**
 * @brief Generate a random key
 * @param key The key to generate
 * @return 0 if successful, -1 if failure
 */
int generate_random_key(char *key) {
  for(int i=0;i<ALPHABET_SIZE;i++)
  {
    key[i]=i+'A';
  }
  for(int i=0;i<ALPHABET_SIZE;i++)
  {
    int j=rand()%ALPHABET_SIZE;
    swap2Positions(key,i,j);
  }
  key[ALPHABET_SIZE]='\0';
  return 0;
}
/**
 * @brief Perform cryptanalysis on a substitution cipher
 * @param ciphertext The ciphertext to analyze
 * @param clen The length of the ciphertext
 * @param plaintext The place to put the plaintext in
 * @param plen The length of the plaintext
 * @param key The place to put the key in
 * @return 0 if successful, -1 if failure
 */
int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {
                                    char alphabet[ALPHABET_SIZE+1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                                    alphabet[ALPHABET_SIZE+1]='\0';
                                    char reverseSwapString[ALPHABET_SIZE+1];
                                    reverseSwapString[ALPHABET_SIZE+1]='\0';
                                   //make a placeholder which stores best plaintext we get so it should be of length one more than plaintext string
                                   char best_plaintext[plen+1];
                                   //make a placeholder which stores best key we get so it should be of length one more than key string
                                   char best_key[ALPHABET_SIZE+1];
                                   double best_chi_sq = DBL_MAX;
                                   double bestLogProb= 0.0-DBL_MAX;
                                   char best_key_log_prob[ALPHABET_SIZE+1];
                                   double computed_freq_not_four_grams[ALPHABET_SIZE] = {0};
                                      compute_letter_frequencies(computed_freq_not_four_grams);
                                  for(int outerTry=0;outerTry<1000;outerTry++)
                                  {
                                    generate_random_key(alphabet);//generate a random key
                                    strcpy(reverseSwapString,alphabet);
                                  for(int i=0;i<400;i++){
                                   int randomFirst=rand()%26;
                                   int randomSecond=rand()%26;
                                   if(randomFirst==randomSecond){
                                    randomFirst=rand()%26;
                                   }
                                   swap2Positions(alphabet,randomFirst,randomSecond);
                                   strcpy(key,alphabet);
                                    cs642Decrypt(CIPHER_SUBS, key, ALPHABET_SIZE, plaintext, plen, ciphertext, clen);//get pertaining plaintext for this candidate key
                                    int freq_not_using_four_grams[ALPHABET_SIZE];
                                            int total_letters;
                                            compute_ciphertext_frequencies(plaintext, clen, freq_not_using_four_grams, &total_letters);
                                            double chi_sq_not_using_four_grams = compute_chi_squared(computed_freq_not_four_grams,freq_not_using_four_grams, total_letters);
                                    char copy[plen];  // Ensure copy has enough space
                                    strcpy(copy, plaintext);
                                    extractFourGrams(plaintext);//extract 4-grams from the plaintext we got from the candidate key
                                    double storeLogValue=applyLogProbability();//apply log probability to the 4-grams we got from the candidate plaintext
                                    if(storeLogValue>bestLogProb){
                                      strcpy(best_key_log_prob,key);
                                      bestLogProb=storeLogValue;
                                    }
                                    for(int j=0;j<fourGramCount;j++)
                                    {
                                      fourGrams[j].frequency=fourGrams[j].frequency/countPlaintextFourGrams;
                                    }
                                    double chiSquareValue= compute_chi_square_4gram(fourGrams, fourGramCount);
                                 // TODO: a remembering mechanism by which we can actually store the best key we have found till yet and can undo any swap which we did for a previous key which gave us a greater chi square value
                                    if(i==0){
                                      strcpy(best_plaintext, copy);
                                      strcpy(best_key, key);
                                      strcpy(reverseSwapString,key);
                                    }
                                    else{
                                      if(chiSquareValue<best_chi_sq){
                                      // if(chi_sq_not_using_four_grams<best_chi_sq){
                                        strcpy(best_plaintext, copy);
                                        strcpy(best_key, key);
                                        best_chi_sq=chi_sq_not_using_four_grams;
                                      }
                                    }
                                  memset(fourGrams, '\0', sizeof(fourGrams));
                                      fourGramCount=0;
                                      countPlaintextFourGrams=0;
                                    }
                                  }
                                    strcpy(key, best_key);
                                    cs642Decrypt(CIPHER_SUBS, key, ALPHABET_SIZE, plaintext, plen, ciphertext, clen);
                                    printf("plaitext from this best key is %s\n",plaintext);
                                    printf("best key is %s\n",best_key);
                                    printf("best key from log value is %s\n",best_key_log_prob);
                                    printf("greatest log value is %f\n",bestLogProb);
                                    // Return successfully
                                    return (0);
}
////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentCleanUp
// Description  : This is a clean up function called at the end of the
//                cryptanalysis of the different ciphers. Use it if you need to
//                release memory you allocated in cs642StudentInit() for
//                instance.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentCleanUp(void) {

  // ADD CODE HERE IF NEEDED

  // Return successfully
  return (0);
}
