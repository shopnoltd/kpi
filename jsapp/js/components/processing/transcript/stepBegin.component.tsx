import React from 'react';
import cx from 'classnames';
import Button from 'js/components/common/button';
import singleProcessingStore from 'js/components/processing/singleProcessingStore';
import bodyStyles from 'js/components/processing/processingBody.module.scss';

export default function StepBegin() {
  function begin() {
    // Make an empty draft.
    singleProcessingStore.setTranscriptDraft({});
  }

  const typeLabel =
    singleProcessingStore.currentQuestionType || t('source file');

  return (
    <div className={cx(bodyStyles.root, bodyStyles.stepBegin)}>
      <header className={bodyStyles.header}>
        {t('This ##type## does not have a transcript yet').replace(
          '##type##',
          typeLabel
        )}
      </header>

      <Button
        type='full'
        color='blue'
        size='l'
        label={t('begin')}
        onClick={begin}
      />
    </div>
  );
}
