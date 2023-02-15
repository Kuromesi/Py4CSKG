"""Train and evaluate the model"""
import os
import torch
import random
import logging
import argparse
import torch.nn as nn
from tqdm import trange, tqdm
from utils.Dataset import *
from transformers.optimization import get_linear_schedule_with_warmup, AdamW
from BERT import *
from config.BERTConfig import *
from utils.metric import *
from utils.logger import *

def train_epoch(model, data_iterator, optimizer, scheduler, config, use_crf=False):
    """Train the model on `steps` batches"""
    # set model to training mode
    model.train()

    # a running average object for loss
    loss_avg = RunningAverage()
    
    # Use tqdm for progress bar
    one_epoch = tqdm(data_iterator)

    for batch, data in enumerate(one_epoch):
        batch_data = data['text_vec']
        batch_tags = data['label_vec']
        # batch_data, batch_token_starts, batch_tags = next(data_iterator)
        batch_masks = data['attention_mask'] # get padding mask

        # compute model output and loss
        logits = model(batch_data, token_type_ids=None, attention_mask=batch_masks, labels=batch_tags, use_crf=use_crf)[0]
        y = batch_tags
        y_pred = logits
        y = y.type(torch.cuda.LongTensor)
        loss = nn.CrossEntropyLoss()
        loss = loss(y_pred, y)

        # clear previous gradients, compute gradients of all variables wrt loss
        model.zero_grad()
        loss.backward()

        # gradient clipping
        nn.utils.clip_grad_norm_(parameters=model.parameters(), max_norm=config.clip_grad)

        # performs updates using calculated gradients
        optimizer.step()
        scheduler.step()

        # update the average loss
        loss_avg.update(loss.item())
        one_epoch.set_postfix(loss='{:05.3f}'.format(loss_avg()))
    

def train_and_evaluate(model, train_data_iterator, val_data_iterator,  optimizer, scheduler, config, model_dir, scorer, test_data_iterator=None, restore_dir=None, use_crf=False):
    """Train the model and evaluate every epoch."""
    # reload weights from restore_dir if specified
    if restore_dir is not None:
        model = BERTCRF.from_pretrained(tagger_model_dir)
        
    best_val_f1 = 0.0
    patience_counter = 0

    for epoch in range(1, config.max_epochs + 1):
        # Run one epoch
        logging.info("Epoch {}/{}".format(epoch, config.max_epochs))

        # Compute number of batches in one epoch
        config.train_steps = config.train_size // config.batch_size
        config.val_steps = config.val_size // config.batch_size

        # Train for one epoch on training set
        train_epoch(model, train_data_iterator, optimizer, scheduler, config, use_crf=use_crf)

        # Evaluate for one epoch on training set and validation set
        config.eval_steps = config.val_steps
        val_metrics = scorer.evaluate(model, val_data_iterator, name='Val')
        
        val_f1 = val_metrics['f1']
        improve_f1 = val_f1 - best_val_f1
        if improve_f1 > 1e-5:    
            logging.info("- Found new best F1")
            best_val_f1 = val_f1
            model.save_pretrained(model_dir)
            if improve_f1 < config.patience:
                patience_counter += 1
            else:
                patience_counter = 0
        else:
            patience_counter += 1

        # Early stopping and logging best f1
        if (patience_counter >= config.patience_num and epoch > config.min_epochs) or epoch == config.max_epochs:
            logging.info("Best val f1: {:05.2f}".format(best_val_f1))
            break
    logging.info(scorer.create_report(model, train_data_iterator))
    logging.info(scorer.create_report(model, val_data_iterator))
    if test_data_iterator:
        logging.info(scorer.create_report(model, test_data_iterator))

if __name__ == '__main__':
    
    # Load configuration
    config = BERTConfig()
    tagger_model_dir = 'trained_models/' + config.name

    # Use GPUs if available
    config.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # Set the random seed for reproducible experiments
    random.seed(config.seed)
    torch.manual_seed(config.seed)
    
    # Set the logger
    set_logger(('src/TextClassification/log/train.log'))
    logging.info("device: {}".format(config.device))

    # Create the input data pipeline
    
    # Initialize the DataLoader
    logging.info("Loading the datasets...")
    dataset = BERTDataset(config)
    dataset.load_data('./myData/learning/CVE2CWE/base/cve.train', './myData/learning/CVE2CWE/base/cve.test')

    train_data = dataset.train_iterator
    val_data = dataset.val_iterator
    test_data = dataset.test_iterator
    # Specify the training and validation dataset sizes
    config.train_size = dataset.train_size
    config.val_size = dataset.val_size

    # Prepare model
    logging.info("Loading BERT model...")

    # Prepare model
    model = BERT.from_pretrained(config.model_name, config, num_labels=config.output_size, ignore_mismatched_sizes=True)
    model.to(config.device)

    # Prepare optimizer
    if config.full_finetuning:
        param_optimizer = list(model.named_parameters())
        no_decay = ['bias', 'LayerNorm.bias', 'LayerNorm.weight']
        optimizer_grouped_parameters = [
            {'params': [p for n, p in param_optimizer if not any(nd in n for nd in no_decay)], 
             'weight_decay': config.weight_decay},
            {'params': [p for n, p in param_optimizer if any(nd in n for nd in no_decay)], 
             'weight_decay': 0.0}
        ]
    else: # only finetune the head classifier
        param_optimizer = list(model.classifier.named_parameters()) 
        optimizer_grouped_parameters = [{'params': [p for n, p in param_optimizer]}]
    
    # BERTCRF
    # bert_optimizer = list(model.bert.named_parameters())
    # classifier_optimizer = list(model.classifier.named_parameters())
    # no_decay = ['bias', 'LayerNorm.bias', 'LayerNorm.weight']
    # optimizer_grouped_parameters = [
    #     {'params': [p for n, p in bert_optimizer if not any(nd in n for nd in no_decay)],
    #         'weight_decay': config.weight_decay},
    #     {'params': [p for n, p in bert_optimizer if any(nd in n for nd in no_decay)],
    #         'weight_decay': 0.0},
    #     {'params': [p for n, p in classifier_optimizer if not any(nd in n for nd in no_decay)],
    #         'lr': config.crf_lr, 'weight_decay': config.weight_decay},
    #     {'params': [p for n, p in classifier_optimizer if any(nd in n for nd in no_decay)],
    #         'lr': config.crf_lr, 'weight_decay': 0.0},
    #     {'params': model.crf.parameters(), 'lr': config.crf_lr}
    # ]

    # BERTBiLSTMCRF
    bert_optimizer = list(model.bert.named_parameters())
    # bilstm_optimizer = list(model.bilstm.named_parameters())
    classifier_optimizer = list(model.classifier.named_parameters())
    no_decay = ['bias', 'LayerNorm.bias', 'LayerNorm.weight']
    optimizer_grouped_parameters = [
        {'params': [p for n, p in bert_optimizer if not any(nd in n for nd in no_decay)],
            'weight_decay': config.weight_decay},
        {'params': [p for n, p in bert_optimizer if any(nd in n for nd in no_decay)],
            'weight_decay': 0.0},
        {'params': [p for n, p in classifier_optimizer if not any(nd in n for nd in no_decay)],
            'lr': config.linear_lr, 'weight_decay': config.weight_decay},
        {'params': [p for n, p in classifier_optimizer if any(nd in n for nd in no_decay)],
            'lr': config.linear_lr, 'weight_decay': 0.0}
    ]

    # optimizer_grouped_parameters = model.parameters()
    # optimizer = torch.optim.Adam(optimizer_grouped_parameters, lr=config.lr, weight_decay=0.001)
    optimizer = AdamW(optimizer_grouped_parameters, lr=config.lr, correct_bias=False)
    train_steps_per_epoch = config.train_size // config.batch_size
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=train_steps_per_epoch, num_training_steps=config.max_epochs * train_steps_per_epoch)


    # Train and evaluate the model
    logging.info("Starting training for {} epoch(s)".format(config.max_epochs))
    scorer = MultiClassScorer()
    # train_and_evaluate(model, train_data, val_data, optimizer, scheduler, config, tagger_model_dir, scorer, args.restore_dir, test_data_iterator=test_data, use_crf=True)
    train_and_evaluate(model, train_data, val_data, optimizer, scheduler, config, tagger_model_dir, scorer, test_data_iterator=test_data, use_crf=True)
