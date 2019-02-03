#include "dispatch.h"
#include <pthread.h>
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include "analysis.h"
#include "sniff.h"
#include <pcap.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <sys/sysinfo.h>

// define the number of threads the thread pool will use
#define THREAD 10

// Check if it is the first dispatch call and enable the threads to run
int first = 0;

// Need to stop execution, CTRL + C used
int clean = 0;

// Create the queue system
struct Node
{
  struct pcap_pkthdr *header;
  unsigned char *packet;
  int verbose;
  struct Node *next;
};

// Store the head, tail and size of our "queue"
struct Node *head = NULL;
struct Node *tail = NULL;
unsigned long size = 0;

// Initialise the threads
pthread_t thread[THREAD];

// Global mutex lock and condition initialisaion
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

// Add a node to the queue
void enqueue(struct Node *node)
{
  // We edit the queue here so we need to lock the threads
  pthread_mutex_lock(&lock);

  // enqueue packet
  // check if queue is empty
  if (head == NULL)
    head = tail = node;
  else
  {
    // create the new tail
    tail->next = node;
    tail = node;
  }
  // increment the size of the queue
  size++;

  // Unblock a thread and signal it that it can dequeue a packet
  // cond signal is sent to 1 thread only
  pthread_cond_signal(&cond);
  pthread_mutex_unlock(&lock);

}

// Take off a packet to be analysed
// This is the function which runs on the threads
void *dequeue(void *args)
{
  // Checks if it can still run
  while (first)
  {
    // we will access and edit global variables here
    pthread_mutex_lock(&lock);
    // Wait for a packet to analyse
    while (size < 1)
    {
      pthread_cond_wait(&cond, &lock);
    }
    // Can it still run ?
    if (first)
    {
      // store the address of the head of the queue in order to free it
      // as it will be overwritten
      struct Node *tmp;
      // Copy the address of the head of the queue
      tmp = head;

      // store a copy of the first node so we can analyse it and
      // free it before other threads try to analyse it
      struct Node *current = (struct Node *) malloc(sizeof(struct Node));
      *current = *head;

      //move the second packet in front of the queue
      if (head == tail)
      {
        head = tail = NULL;
      } else {
        head = head->next;
      }
      size--;

      // free the original head node
      free(tmp);

      // unlock the thread for other threads to continue working as
      // it is safe to run the rest of this code
      pthread_mutex_unlock(&lock);
      // Cannot use temp as it would cause issues
      analyse(current->header, current->packet, current->verbose);
      // free the "current" node
      free(current->header);
      free(current->packet);
      free(current);
    } else
    {
      // unlock mutex so the other threads can also stop running
      pthread_mutex_unlock(&lock);
    }
  }
  return (void *) args;
}

void handler(int signo)
{
  // clean up if the signal is received
  if (signo == SIGINT)
    clean = 1;
  printf("\nSend another packet to stop the program.\n");
}

// Clean up the threads
void free_threads()
{
  // lock the global variables
  pthread_mutex_lock(&lock);
  // make working threads stop working
  first = 0;
  // prevent threads from looping waiting for a packet
  size = 1;
  // threads are now stopping, need to break the wait for cond loop
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&lock);

  // destroy the mutexes
  pthread_mutex_destroy(&lock);
  pthread_cond_destroy(&cond);

  // Rejoin the threads
  int i;
  for (i = 0; i < THREAD ; i++)
  {
    pthread_join(thread[i], (void *) NULL);
  }
}

void dispatch(const struct pcap_pkthdr *header, const unsigned char *packet, int verbose)
{
  // create threads on first call
  if (first == 0)
  {
    // prevent creating threads again
    first++;
    int i;
    for(i = 0; i < THREAD; i++)
    {
      if (pthread_create(&thread[i], NULL, &dequeue, (void *) NULL))
      {
        printf("Error when creating thread %d\n", i);
      }
    }
  }

  // Catch an exit signal to print the resume of malicious activities
  if(signal(SIGINT, handler) == SIG_ERR)
    printf("Error catching SIGINT\n");

  // clean the program to get ready for exit
  if (clean == 1)
  {
    // free the pcap_handle
    free_pcap_handle();
    // Join the threads
    free_threads();
    // Print the resume
    print_resume();
    // exit
    exit(EXIT_SUCCESS);
  }

  // Allocate the necessary memory for a node and its elements
  struct Node* sendPacket = (struct Node *) malloc(sizeof(struct Node));
  sendPacket->header = (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr));
  sendPacket->header->len = header->len;

  // Packet data are chars so using calloc while ensure that the data is prensent
  // Allocate more memory to get the last '\0' symbol
  sendPacket->packet = (unsigned char *) calloc(sendPacket->header->len + 2, sizeof(char));
  // Copy the data over
  memcpy(sendPacket->packet, packet, sendPacket->header->len);

  sendPacket->verbose = verbose;
  sendPacket->next = NULL;

  // send the copied packet as a Node
  enqueue(sendPacket);
}
